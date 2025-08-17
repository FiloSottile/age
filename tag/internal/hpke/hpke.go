// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpke

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"hash"
	"math/bits"

	"golang.org/x/crypto/chacha20poly1305"
)

type KEMSender interface {
	Encap() (sharedSecret, enc []byte, err error)
	ID() uint16
}

type KEMRecipient interface {
	Decap(enc []byte) (sharedSecret []byte, err error)
	ID() uint16
}

type dhKEM struct {
	kdf     KDF
	id      uint16
	nSecret uint16
}

func (dh *dhKEM) extractAndExpand(dhKey, kemContext []byte) ([]byte, error) {
	suiteID := binary.BigEndian.AppendUint16([]byte("KEM"), dh.id)
	eaePRK, err := dh.kdf.LabeledExtract(suiteID, nil, "eae_prk", dhKey)
	if err != nil {
		return nil, err
	}
	return dh.kdf.LabeledExpand(suiteID, eaePRK, "shared_secret", kemContext, dh.nSecret)
}

func (dh *dhKEM) ID() uint16 {
	return dh.id
}

type dhkemSender struct {
	dhKEM
	pub *ecdh.PublicKey
}

// DHKEMSender returns a KEMSender implementing DHKEM(P-256, HKDF-SHA256).
func DHKEMSender(pub *ecdh.PublicKey) (KEMSender, error) {
	switch pub.Curve() {
	case ecdh.P256():
		return &dhkemSender{
			pub: pub,
			dhKEM: dhKEM{
				kdf:     HKDFSHA256(),
				id:      0x0010,
				nSecret: 32,
			},
		}, nil
	default:
		return nil, errors.New("unsupported curve")
	}
}

// testingOnlyGenerateKey is only used during testing, to provide
// a fixed test key to use when checking the RFC 9180 vectors.
var testingOnlyGenerateKey func() *ecdh.PrivateKey

func (dh *dhkemSender) Encap() (sharedSecret []byte, encapPub []byte, err error) {
	privEph, err := dh.pub.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if testingOnlyGenerateKey != nil {
		privEph = testingOnlyGenerateKey()
	}
	dhVal, err := privEph.ECDH(dh.pub)
	if err != nil {
		return nil, nil, err
	}
	encPubEph := privEph.PublicKey().Bytes()

	encPubRecip := dh.pub.Bytes()
	kemContext := append(encPubEph, encPubRecip...)
	sharedSecret, err = dh.extractAndExpand(dhVal, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return sharedSecret, encPubEph, nil
}

type dhkemRecipient struct {
	dhKEM
	priv *ecdh.PrivateKey
}

// DHKEMRecipient returns a KEMRecipient implementing DHKEM(P-256, HKDF-SHA256).
func DHKEMRecipient(priv *ecdh.PrivateKey) (KEMRecipient, error) {
	switch priv.Curve() {
	case ecdh.P256():
		return &dhkemRecipient{
			priv: priv,
			dhKEM: dhKEM{
				kdf:     HKDFSHA256(),
				id:      0x0010,
				nSecret: 32,
			},
		}, nil
	default:
		return nil, errors.New("unsupported curve")
	}
}

func (dh *dhkemRecipient) Decap(encPubEph []byte) ([]byte, error) {
	pubEph, err := dh.priv.Curve().NewPublicKey(encPubEph)
	if err != nil {
		return nil, err
	}
	dhVal, err := dh.priv.ECDH(pubEph)
	if err != nil {
		return nil, err
	}
	kemContext := append(encPubEph, dh.priv.PublicKey().Bytes()...)
	return dh.extractAndExpand(dhVal, kemContext)
}

type qsf struct {
	id    uint16
	label string
}

func (q *qsf) ID() uint16 {
	return q.id
}

func (q *qsf) sharedSecret(ssPQ, ssT, ctT, ekT []byte) []byte {
	h := sha3.New256()
	h.Write(ssPQ)
	h.Write(ssT)
	h.Write(ctT)
	h.Write(ekT)
	h.Write([]byte(q.label))
	return h.Sum(nil)
}

type qsfSender struct {
	qsf
	t  *ecdh.PublicKey
	pq *mlkem.EncapsulationKey768
}

// QSFSender returns a KEMSender implementing QSF-P256-MLKEM768-SHAKE256-SHA3256
// or QSF-X25519-MLKEM768-SHA3256-SHAKE256 (aka X-Wing) from draft-ietf-hpke-pq
// and draft-irtf-cfrg-concrete-hybrid-kems-00.
func QSFSender(t *ecdh.PublicKey, pq *mlkem.EncapsulationKey768) (KEMSender, error) {
	switch t.Curve() {
	case ecdh.P256():
		return &qsfSender{
			t: t, pq: pq,
			qsf: qsf{
				id:    0x0050,
				label: "QSF-P256-MLKEM768-SHAKE256-SHA3256",
			},
		}, nil
	case ecdh.X25519():
		return &qsfSender{
			t: t, pq: pq,
			qsf: qsf{
				id: 0x647a,
				label: /**/ `\./` +
					/*   */ `/^\`,
			},
		}, nil
	default:
		return nil, errors.New("unsupported curve")
	}
}

var testingOnlyEncapsulate func() (ss, ct []byte)

func (s *qsfSender) Encap() (sharedSecret []byte, encapPub []byte, err error) {
	skE, err := s.t.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if testingOnlyGenerateKey != nil {
		skE = testingOnlyGenerateKey()
	}
	ssT, err := skE.ECDH(s.t)
	if err != nil {
		return nil, nil, err
	}
	ctT := skE.PublicKey().Bytes()

	ssPQ, ctPQ := s.pq.Encapsulate()
	if testingOnlyEncapsulate != nil {
		ssPQ, ctPQ = testingOnlyEncapsulate()
	}

	ss := s.sharedSecret(ssPQ, ssT, ctT, s.t.Bytes())
	ct := append(ctPQ, ctT...)
	return ss, ct, nil
}

type qsfRecipient struct {
	qsf
	t  *ecdh.PrivateKey
	pq *mlkem.DecapsulationKey768
}

// QSFRecipient returns a KEMRecipient implementing QSF-P256-MLKEM768-SHAKE256-SHA3256
// or QSF-MLKEM768-X25519-SHA3256-SHAKE256 (aka X-Wing) from draft-ietf-hpke-pq
// and draft-irtf-cfrg-concrete-hybrid-kems-00.
func QSFRecipient(t *ecdh.PrivateKey, pq *mlkem.DecapsulationKey768) (KEMRecipient, error) {
	switch t.Curve() {
	case ecdh.P256():
		return &qsfRecipient{
			t: t, pq: pq,
			qsf: qsf{
				id:    0x0050,
				label: "QSF-P256-MLKEM768-SHAKE256-SHA3256",
			},
		}, nil
	case ecdh.X25519():
		return &qsfRecipient{
			t: t, pq: pq,
			qsf: qsf{
				id: 0x647a,
				label: /**/ `\./` +
					/*   */ `/^\`,
			},
		}, nil
	default:
		return nil, errors.New("unsupported curve")
	}
}

func (r *qsfRecipient) Decap(enc []byte) ([]byte, error) {
	ctPQ, ctT := enc[:mlkem.CiphertextSize768], enc[mlkem.CiphertextSize768:]
	ssPQ, err := r.pq.Decapsulate(ctPQ)
	if err != nil {
		return nil, err
	}
	pub, err := r.t.Curve().NewPublicKey(ctT)
	if err != nil {
		return nil, err
	}
	ssT, err := r.t.ECDH(pub)
	if err != nil {
		return nil, err
	}
	ss := r.sharedSecret(ssPQ, ssT, ctT, r.t.PublicKey().Bytes())
	return ss, nil
}

type KDF interface {
	LabeledExtract(sid, salt []byte, label string, inputKey []byte) ([]byte, error)
	LabeledExpand(suiteID, randomKey []byte, label string, info []byte, length uint16) ([]byte, error)
	ID() uint16
}

type hkdfKDF struct {
	hash func() hash.Hash
	id   uint16
}

func HKDFSHA256() KDF {
	return &hkdfKDF{hash: sha256.New, id: 0x0001}
}

func (kdf *hkdfKDF) ID() uint16 {
	return kdf.id
}

func (kdf *hkdfKDF) LabeledExtract(sid []byte, salt []byte, label string, inputKey []byte) ([]byte, error) {
	labeledIKM := make([]byte, 0, 7+len(sid)+len(label)+len(inputKey))
	labeledIKM = append(labeledIKM, []byte("HPKE-v1")...)
	labeledIKM = append(labeledIKM, sid...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, inputKey...)
	return hkdf.Extract(kdf.hash, labeledIKM, salt)
}

func (kdf *hkdfKDF) LabeledExpand(suiteID []byte, randomKey []byte, label string, info []byte, length uint16) ([]byte, error) {
	labeledInfo := make([]byte, 0, 2+7+len(suiteID)+len(label)+len(info))
	labeledInfo = binary.BigEndian.AppendUint16(labeledInfo, length)
	labeledInfo = append(labeledInfo, []byte("HPKE-v1")...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return hkdf.Expand(kdf.hash, randomKey, string(labeledInfo), int(length))
}

type AEAD interface {
	AEAD(key []byte) (cipher.AEAD, error)
	KeySize() int
	NonceSize() int
	ID() uint16
}

type aead struct {
	keySize   int
	nonceSize int
	aead      func([]byte) (cipher.AEAD, error)
	id        uint16
}

func ChaCha20Poly1305() AEAD {
	return &aead{
		keySize:   chacha20poly1305.KeySize,
		nonceSize: chacha20poly1305.NonceSize,
		aead:      chacha20poly1305.New,
		id:        0x0003,
	}
}

func (a *aead) ID() uint16 {
	return a.id
}

func (a *aead) AEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != a.keySize {
		return nil, errors.New("invalid key size")
	}
	return a.aead(key)
}

func (a *aead) KeySize() int {
	return a.keySize
}

func (a *aead) NonceSize() int {
	return a.nonceSize
}

type context struct {
	aead    cipher.AEAD
	suiteID []byte

	key       []byte
	baseNonce []byte

	seqNum uint128
}

type Sender struct {
	*context
}

type Recipient struct {
	*context
}

func newContext(sharedSecret []byte, kemID uint16, kdf KDF, aead AEAD, info []byte) (*context, error) {
	sid := suiteID(kemID, kdf.ID(), aead.ID())

	pskIDHash, err := kdf.LabeledExtract(sid, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, err
	}
	infoHash, err := kdf.LabeledExtract(sid, nil, "info_hash", info)
	if err != nil {
		return nil, err
	}
	ksContext := append([]byte{0}, pskIDHash...)
	ksContext = append(ksContext, infoHash...)

	secret, err := kdf.LabeledExtract(sid, sharedSecret, "secret", nil)
	if err != nil {
		return nil, err
	}
	key, err := kdf.LabeledExpand(sid, secret, "key", ksContext, uint16(aead.KeySize()))
	if err != nil {
		return nil, err
	}
	baseNonce, err := kdf.LabeledExpand(sid, secret, "base_nonce", ksContext, uint16(aead.NonceSize()))
	if err != nil {
		return nil, err
	}

	a, err := aead.AEAD(key)
	if err != nil {
		return nil, err
	}

	return &context{
		aead:      a,
		suiteID:   sid,
		key:       key,
		baseNonce: baseNonce,
	}, nil
}

func SetupSender(kem KEMSender, kdf KDF, aead AEAD, info []byte) ([]byte, *Sender, error) {
	sharedSecret, encapsulatedKey, err := kem.Encap()
	if err != nil {
		return nil, nil, err
	}
	context, err := newContext(sharedSecret, kem.ID(), kdf, aead, info)
	if err != nil {
		return nil, nil, err
	}
	return encapsulatedKey, &Sender{context}, nil
}

func SetupRecipient(kem KEMRecipient, kdf KDF, aead AEAD, info, enc []byte) (*Recipient, error) {
	sharedSecret, err := kem.Decap(enc)
	if err != nil {
		return nil, err
	}
	context, err := newContext(sharedSecret, kem.ID(), kdf, aead, info)
	if err != nil {
		return nil, err
	}
	return &Recipient{context}, nil
}

func (ctx *context) nextNonce() []byte {
	nonce := ctx.seqNum.bytes()[16-ctx.aead.NonceSize():]
	for i := range ctx.baseNonce {
		nonce[i] ^= ctx.baseNonce[i]
	}
	return nonce
}

func (ctx *context) incrementNonce() {
	ctx.seqNum = ctx.seqNum.addOne()
}

func (s *Sender) Seal(aad, plaintext []byte) ([]byte, error) {
	ciphertext := s.aead.Seal(nil, s.nextNonce(), plaintext, aad)
	s.incrementNonce()
	return ciphertext, nil
}

func (r *Recipient) Open(aad, ciphertext []byte) ([]byte, error) {
	plaintext, err := r.aead.Open(nil, r.nextNonce(), ciphertext, aad)
	if err != nil {
		return nil, err
	}
	r.incrementNonce()
	return plaintext, nil
}

func suiteID(kemID, kdfID, aeadID uint16) []byte {
	suiteID := make([]byte, 0, 4+2+2+2)
	suiteID = append(suiteID, []byte("HPKE")...)
	suiteID = binary.BigEndian.AppendUint16(suiteID, kemID)
	suiteID = binary.BigEndian.AppendUint16(suiteID, kdfID)
	suiteID = binary.BigEndian.AppendUint16(suiteID, aeadID)
	return suiteID
}

type uint128 struct {
	hi, lo uint64
}

func (u uint128) addOne() uint128 {
	lo, carry := bits.Add64(u.lo, 1, 0)
	return uint128{u.hi + carry, lo}
}

func (u uint128) bytes() []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:], u.hi)
	binary.BigEndian.PutUint64(b[8:], u.lo)
	return b
}
