// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package age

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/FiloSottile/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

const oaepLabel = "age-tool.com ssh-rsa"

type SSHRSARecipient struct {
	sshKey ssh.PublicKey
	pubKey *rsa.PublicKey
}

var _ Recipient = &SSHRSARecipient{}

func (*SSHRSARecipient) Type() string { return "ssh-rsa" }

func NewSSHRSARecipient(pk ssh.PublicKey) (*SSHRSARecipient, error) {
	if pk.Type() != "ssh-rsa" {
		return nil, errors.New("SSH public key is not an RSA key")
	}
	r := &SSHRSARecipient{
		sshKey: pk,
	}

	if pk, ok := pk.(ssh.CryptoPublicKey); ok {
		if pk, ok := pk.CryptoPublicKey().(*rsa.PublicKey); ok {
			r.pubKey = pk
		} else {
			return nil, errors.New("unexpected public key type")
		}
	} else {
		return nil, errors.New("pk does not implement ssh.CryptoPublicKey")
	}
	return r, nil
}

func (r *SSHRSARecipient) Wrap(fileKey []byte) (*format.Recipient, error) {
	h := sha256.New()
	h.Write(r.sshKey.Marshal())
	hh := h.Sum(nil)

	l := &format.Recipient{
		Type: "ssh-rsa",
		Args: []string{format.EncodeToString(hh[:4])},
	}

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
		r.pubKey, fileKey, []byte(oaepLabel))
	if err != nil {
		return nil, err
	}
	l.Body = []byte(format.EncodeToString(wrappedKey) + "\n")

	return l, nil
}

type SSHRSAIdentity struct {
	k      *rsa.PrivateKey
	sshKey ssh.PublicKey
}

var _ Identity = &SSHRSAIdentity{}

func (*SSHRSAIdentity) Type() string { return "ssh-rsa" }

func NewSSHRSAIdentity(key *rsa.PrivateKey) (*SSHRSAIdentity, error) {
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	i := &SSHRSAIdentity{
		k: key, sshKey: s.PublicKey(),
	}
	return i, nil
}

func (i *SSHRSAIdentity) Unwrap(block *format.Recipient) ([]byte, error) {
	if block.Type != "ssh-rsa" {
		return nil, errors.New("wrong recipient block type")
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid ssh-rsa recipient block")
	}
	hash, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh-rsa recipient: %v", err)
	}
	if len(hash) != 4 {
		return nil, errors.New("invalid ssh-rsa recipient block")
	}
	wrappedKey, err := format.DecodeString(string(block.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh-rsa recipient: %v", err)
	}

	h := sha256.New()
	h.Write(i.sshKey.Marshal())
	hh := h.Sum(nil)
	if !bytes.Equal(hh[:4], hash) {
		return nil, errors.New("wrong ssh-rsa key")
	}

	fileKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, i.k,
		wrappedKey, []byte(oaepLabel))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key: %v", err)
	}
	return fileKey, nil
}

type SSHEd25519Recipient struct {
	sshKey         ssh.PublicKey
	theirPublicKey [32]byte
}

var _ Recipient = &SSHEd25519Recipient{}

func (*SSHEd25519Recipient) Type() string { return "ssh-ed25519" }

func NewSSHEd25519Recipient(pk ssh.PublicKey) (*SSHEd25519Recipient, error) {
	if pk.Type() != "ssh-ed25519" {
		return nil, errors.New("SSH public key is not an Ed25519 key")
	}
	r := &SSHEd25519Recipient{
		sshKey: pk,
	}

	if pk, ok := pk.(ssh.CryptoPublicKey); ok {
		if pk, ok := pk.CryptoPublicKey().(ed25519.PublicKey); ok {
			pubKey := ed25519PublicKeyToCurve25519(pk)
			copy(r.theirPublicKey[:], pubKey)
		} else {
			return nil, errors.New("unexpected public key type")
		}
	} else {
		return nil, errors.New("pk does not implement ssh.CryptoPublicKey")
	}
	return r, nil
}

func ParseSSHRecipient(s string) (Recipient, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("malformed SSH recipient: %q: %v", s, err)
	}

	var r Recipient
	switch t := pubKey.Type(); t {
	case "ssh-rsa":
		r, err = NewSSHRSARecipient(pubKey)
	case "ssh-ed25519":
		r, err = NewSSHEd25519Recipient(pubKey)
	default:
		return nil, fmt.Errorf("unknown SSH recipient type: %q", t)
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH recipient: %q: %v", s, err)
	}

	return r, nil
}

var curve25519P, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) []byte {
	// ed25519.PublicKey is a little endian representation of the y-coordinate,
	// with the most significant bit set based on the sign of the x-ccordinate.
	bigEndianY := make([]byte, ed25519.PublicKeySize)
	for i, b := range pk {
		bigEndianY[ed25519.PublicKeySize-i-1] = b
	}
	bigEndianY[0] &= 0b0111_1111

	// The Montgomery u-coordinate is derived through the bilinear map
	//
	//     u = (1 + y) / (1 - y)
	//
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption.
	y := new(big.Int).SetBytes(bigEndianY)
	denom := big.NewInt(1)
	denom.ModInverse(denom.Sub(denom, y), curve25519P) // 1 / (1 - y)
	u := y.Mul(y.Add(y, big.NewInt(1)), denom)
	u.Mod(u, curve25519P)

	out := make([]byte, 32)
	uBytes := u.Bytes()
	for i, b := range uBytes {
		out[len(uBytes)-i-1] = b
	}

	return out
}

const ed25519Label = "age-tool.com ssh-ed25519"

func (r *SSHEd25519Recipient) Wrap(fileKey []byte) (*format.Recipient, error) {
	// TODO: DRY this up with the X25519 implementation.
	var ephemeral, ourPublicKey [32]byte
	if _, err := rand.Read(ephemeral[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&ourPublicKey, &ephemeral)

	var sharedSecret, tweak [32]byte
	tH := hkdf.New(sha256.New, nil, r.sshKey.Marshal(), []byte(ed25519Label))
	if _, err := io.ReadFull(tH, tweak[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarMult(&sharedSecret, &ephemeral, &r.theirPublicKey)
	curve25519.ScalarMult(&sharedSecret, &tweak, &sharedSecret)

	sH := sha256.New()
	sH.Write(r.sshKey.Marshal())
	hh := sH.Sum(nil)

	l := &format.Recipient{
		Type: "ssh-ed25519",
		Args: []string{format.EncodeToString(hh[:4]),
			format.EncodeToString(ourPublicKey[:])},
	}

	salt := make([]byte, 0, 32*2)
	salt = append(salt, ourPublicKey[:]...)
	salt = append(salt, r.theirPublicKey[:]...)
	h := hkdf.New(sha256.New, sharedSecret[:], salt, []byte(ed25519Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = []byte(format.EncodeToString(wrappedKey) + "\n")

	return l, nil
}

type SSHEd25519Identity struct {
	secretKey, ourPublicKey [32]byte
	sshKey                  ssh.PublicKey
}

var _ Identity = &SSHEd25519Identity{}

func (*SSHEd25519Identity) Type() string { return "ssh-ed25519" }

func NewSSHEd25519Identity(key ed25519.PrivateKey) (*SSHEd25519Identity, error) {
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	i := &SSHEd25519Identity{
		sshKey: s.PublicKey(),
	}
	secretKey := ed25519PrivateKeyToCurve25519(key)
	copy(i.secretKey[:], secretKey)
	curve25519.ScalarBaseMult(&i.ourPublicKey, &i.secretKey)
	return i, nil
}

func ParseSSHIdentity(pemBytes []byte) (Identity, error) {
	k, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	switch k := k.(type) {
	case *ed25519.PrivateKey:
		return NewSSHEd25519Identity(*k)
	case *rsa.PrivateKey:
		return NewSSHRSAIdentity(k)
	}

	return nil, fmt.Errorf("unsupported SSH identity type: %T", k)
}

func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) []byte {
	h := sha512.New()
	h.Write(pk[:32])
	out := h.Sum(nil)
	return out[:32]
}

func (i *SSHEd25519Identity) Unwrap(block *format.Recipient) ([]byte, error) {
	// TODO: DRY this up with the X25519 implementation.
	if block.Type != "ssh-ed25519" {
		return nil, errors.New("wrong recipient block type")
	}
	if len(block.Args) != 2 {
		return nil, errors.New("invalid ssh-ed25519 recipient block")
	}
	hash, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh-ed25519 recipient: %v", err)
	}
	if len(hash) != 4 {
		return nil, errors.New("invalid ssh-ed25519 recipient block")
	}
	publicKey, err := format.DecodeString(block.Args[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh-ed25519 recipient: %v", err)
	}
	if len(publicKey) != 32 {
		return nil, errors.New("invalid ssh-ed25519 recipient block")
	}
	wrappedKey, err := format.DecodeString(string(block.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh-ed25519 recipient: %v", err)
	}

	sH := sha256.New()
	sH.Write(i.sshKey.Marshal())
	hh := sH.Sum(nil)
	if !bytes.Equal(hh[:4], hash) {
		return nil, errors.New("wrong ssh-ed25519 key")
	}

	var sharedSecret, theirPublicKey, tweak [32]byte
	copy(theirPublicKey[:], publicKey)
	tH := hkdf.New(sha256.New, nil, i.sshKey.Marshal(), []byte(ed25519Label))
	if _, err := io.ReadFull(tH, tweak[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarMult(&sharedSecret, &i.secretKey, &theirPublicKey)
	curve25519.ScalarMult(&sharedSecret, &tweak, &sharedSecret)

	salt := make([]byte, 0, 32*2)
	salt = append(salt, theirPublicKey[:]...)
	salt = append(salt, i.ourPublicKey[:]...)
	h := hkdf.New(sha256.New, sharedSecret[:], salt, []byte(ed25519Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	fileKey, err := aeadDecrypt(wrappingKey, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key: %v", err)
	}
	return fileKey, nil
}
