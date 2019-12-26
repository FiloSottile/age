// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package age

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"

	"filippo.io/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

func SSHFingerprint(pk ssh.PublicKey) string {
	h := sha256.New()
	h.Write(pk.Marshal())
	hh := h.Sum(nil)
	return format.EncodeToString(hh[:4])
}

const oaepLabel = "age-encryption.org/v1/ssh-rsa"

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
	l := &format.Recipient{
		Type: "ssh-rsa",
		Args: []string{SSHFingerprint(r.sshKey)},
	}

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
		r.pubKey, fileKey, []byte(oaepLabel))
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

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
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid ssh-rsa recipient block")
	}

	if block.Args[0] != SSHFingerprint(i.sshKey) {
		return nil, ErrIncorrectIdentity
	}

	fileKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, i.k,
		block.Body, []byte(oaepLabel))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key: %v", err)
	}
	return fileKey, nil
}

type SSHEd25519Recipient struct {
	sshKey         ssh.PublicKey
	theirPublicKey []byte
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
			r.theirPublicKey = ed25519PublicKeyToCurve25519(pk)
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
	// with the most significant bit set based on the sign of the x-coordinate.
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

	out := make([]byte, curve25519.PointSize)
	uBytes := u.Bytes()
	for i, b := range uBytes {
		out[len(uBytes)-i-1] = b
	}

	return out
}

const ed25519Label = "age-encryption.org/v1/ssh-ed25519"

func (r *SSHEd25519Recipient) Wrap(fileKey []byte) (*format.Recipient, error) {
	ephemeral := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(ephemeral); err != nil {
		return nil, err
	}
	ourPublicKey, err := curve25519.X25519(ephemeral, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := curve25519.X25519(ephemeral, r.theirPublicKey)
	if err != nil {
		return nil, err
	}

	tweak := make([]byte, curve25519.ScalarSize)
	tH := hkdf.New(sha256.New, nil, r.sshKey.Marshal(), []byte(ed25519Label))
	if _, err := io.ReadFull(tH, tweak); err != nil {
		return nil, err
	}
	sharedSecret, _ = curve25519.X25519(tweak, sharedSecret)

	l := &format.Recipient{
		Type: "ssh-ed25519",
		Args: []string{SSHFingerprint(r.sshKey),
			format.EncodeToString(ourPublicKey[:])},
	}

	salt := make([]byte, 0, len(ourPublicKey)+len(r.theirPublicKey))
	salt = append(salt, ourPublicKey...)
	salt = append(salt, r.theirPublicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(ed25519Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return l, nil
}

type SSHEd25519Identity struct {
	secretKey, ourPublicKey []byte
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
		sshKey:    s.PublicKey(),
		secretKey: ed25519PrivateKeyToCurve25519(key),
	}
	i.ourPublicKey, _ = curve25519.X25519(i.secretKey, curve25519.Basepoint)
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
	h.Write(pk.Seed())
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
}

func (i *SSHEd25519Identity) Unwrap(block *format.Recipient) ([]byte, error) {
	if block.Type != "ssh-ed25519" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 2 {
		return nil, errors.New("invalid ssh-ed25519 recipient block")
	}
	publicKey, err := format.DecodeString(block.Args[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh-ed25519 recipient: %v", err)
	}
	if len(publicKey) != curve25519.PointSize {
		return nil, errors.New("invalid ssh-ed25519 recipient block")
	}

	if block.Args[0] != SSHFingerprint(i.sshKey) {
		return nil, ErrIncorrectIdentity
	}

	sharedSecret, err := curve25519.X25519(i.secretKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 recipient: %v", err)
	}

	tweak := make([]byte, curve25519.ScalarSize)
	tH := hkdf.New(sha256.New, nil, i.sshKey.Marshal(), []byte(ed25519Label))
	if _, err := io.ReadFull(tH, tweak); err != nil {
		return nil, err
	}
	sharedSecret, _ = curve25519.X25519(tweak, sharedSecret)

	salt := make([]byte, 0, len(publicKey)+len(i.ourPublicKey))
	salt = append(salt, publicKey...)
	salt = append(salt, i.ourPublicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(ed25519Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	fileKey, err := aeadDecrypt(wrappingKey, block.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key: %v", err)
	}
	return fileKey, nil
}
