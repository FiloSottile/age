// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package agessh provides age.Identity and age.Recipient implementations of
// types "ssh-rsa" and "ssh-ed25519", which allow reusing existing SSH keys for
// encryption with age-encryption.org/v1.
//
// These recipient types should only be used for compatibility with existing
// keys, and native X25519 keys should be preferred otherwise.
//
// Note that these recipient types are not anonymous: the encrypted message will
// include a short 32-bit ID of the public key.
package agessh

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/internal/format"
	"filippo.io/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

func sshFingerprint(pk ssh.PublicKey) string {
	h := sha256.Sum256(pk.Marshal())
	return format.EncodeToString(h[:4])
}

const oaepLabel = "age-encryption.org/v1/ssh-rsa"

type RSARecipient struct {
	sshKey ssh.PublicKey
	pubKey *rsa.PublicKey
}

var _ age.Recipient = &RSARecipient{}

func NewRSARecipient(pk ssh.PublicKey) (*RSARecipient, error) {
	if pk.Type() != "ssh-rsa" {
		return nil, errors.New("SSH public key is not an RSA key")
	}
	r := &RSARecipient{
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
	if r.pubKey.Size() < 2048/8 {
		return nil, errors.New("RSA key size is too small")
	}
	return r, nil
}

func (r *RSARecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	l := &age.Stanza{
		Type: "ssh-rsa",
		Args: []string{sshFingerprint(r.sshKey)},
	}

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
		r.pubKey, fileKey, []byte(oaepLabel))
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return []*age.Stanza{l}, nil
}

type RSAIdentity struct {
	k      *rsa.PrivateKey
	sshKey ssh.PublicKey
}

var _ age.Identity = &RSAIdentity{}

func NewRSAIdentity(key *rsa.PrivateKey) (*RSAIdentity, error) {
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	i := &RSAIdentity{
		k: key, sshKey: s.PublicKey(),
	}
	return i, nil
}

func (i *RSAIdentity) Recipient() *RSARecipient {
	return &RSARecipient{
		sshKey: i.sshKey,
		pubKey: &i.k.PublicKey,
	}
}

func (i *RSAIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *RSAIdentity) unwrap(block *age.Stanza) ([]byte, error) {
	if block.Type != "ssh-rsa" {
		return nil, age.ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid ssh-rsa recipient block")
	}

	if block.Args[0] != sshFingerprint(i.sshKey) {
		return nil, age.ErrIncorrectIdentity
	}

	fileKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, i.k,
		block.Body, []byte(oaepLabel))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key: %v", err)
	}
	return fileKey, nil
}

type Ed25519Recipient struct {
	sshKey ssh.PublicKey
	k      *ecdh.PublicKey
}

var _ age.Recipient = &Ed25519Recipient{}

func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) ([]byte, error) {
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption and
	// https://pkg.go.dev/filippo.io/edwards25519#Point.BytesMontgomery.
	p, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

func NewEd25519Recipient(pk ssh.PublicKey) (*Ed25519Recipient, error) {
	if pk.Type() != "ssh-ed25519" {
		return nil, errors.New("SSH public key is not an Ed25519 key")
	}

	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("pk does not implement ssh.CryptoPublicKey")
	}
	epk, ok := cpk.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("unexpected public key type")
	}
	mpk, err := ed25519PublicKeyToCurve25519(epk)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 public key: %v", err)
	}
	k, err := ecdh.X25519().NewPublicKey(mpk)
	if err != nil {
		return nil, err
	}
	return &Ed25519Recipient{
		sshKey: pk,
		k:      k,
	}, nil
}

type ECDSARecipient struct {
	sshKey ssh.PublicKey
	k      *ecdh.PublicKey
}

var _ age.Recipient = &ECDSARecipient{}

func NewECDSARecipient(pk ssh.PublicKey) (*ECDSARecipient, error) {
	if pk.Type() != "ecdsa-sha2-nistp521" && pk.Type() != "ecdsa-sha2-nistp384" && pk.Type() != "ecdsa-sha2-nistp256" {
		return nil, errors.New("SSH public key is not an ECDSA key")
	}

	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("pk does not implement ssh.CryptoPublicKey")
	}
	epk, ok := cpk.CryptoPublicKey().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("unexpected public key type")
	}
	k, err := epk.ECDH()
	if err != nil {
		return nil, err
	}
	return &ECDSARecipient{
		sshKey: pk,
		k:      k,
	}, nil
}

const ecdsanistp256Label = "age-encryption.org/v1/ecdsa-sha2-nistp256"
const ecdsanistp384Label = "age-encryption.org/v1/ecdsa-sha2-nistp384"
const ecdsanistp521Label = "age-encryption.org/v1/ecdsa-sha2-nistp521"

func labelForEcdsaCurve(c ecdh.Curve) string {
	switch c {
	case ecdh.P256():
		return ecdsanistp256Label
	case ecdh.P384():
		return ecdsanistp384Label
	case ecdh.P521():
		return ecdsanistp521Label
	}
	return ""
}
func (r *ECDSARecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	ephemeral, err := r.k.Curve().GenerateKey(rand.Reader)

	ourPublicKey := ephemeral.PublicKey()
	if err != nil {
		return nil, err
	}

	sharedSecret, err := ephemeral.ECDH(r.k)
	if err != nil {
		return nil, err
	}

	l := &age.Stanza{
		Type: r.sshKey.Type(),
		Args: []string{sshFingerprint(r.sshKey),
			format.EncodeToString(ourPublicKey.Bytes()[:])},
	}
	// here we are not doing the key distancing (tweak) that was done
	// for ssh-ed25519 keys, as it does not improve security
	salt := make([]byte, 0, len(ourPublicKey.Bytes())+len(r.k.Bytes()))
	salt = append(salt, ourPublicKey.Bytes()...)
	salt = append(salt, r.k.Bytes()...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(labelForEcdsaCurve(r.k.Curve())))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return []*age.Stanza{l}, nil
}

func ParseRecipient(s string) (age.Recipient, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("malformed SSH recipient: %q: %v", s, err)
	}

	var r age.Recipient
	switch t := pubKey.Type(); t {
	case "ssh-rsa":
		r, err = NewRSARecipient(pubKey)
	case "ssh-ed25519":
		r, err = NewEd25519Recipient(pubKey)
	case "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256":
		r, err = NewECDSARecipient(pubKey)
	default:
		return nil, fmt.Errorf("unknown SSH recipient type: %q", t)
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH recipient: %q: %v", s, err)
	}

	return r, nil
}

const ed25519Label = "age-encryption.org/v1/ssh-ed25519"

func (r *Ed25519Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)

	ourPublicKey := ephemeral.PublicKey()
	if err != nil {
		return nil, err
	}

	// .ECDH does the same as curve25519.X25519(ephemeral, theirPublicKey)
	sharedSecret, err := ephemeral.ECDH(r.k)
	if err != nil {
		return nil, err
	}

	l := &age.Stanza{
		Type: "ssh-ed25519",
		Args: []string{sshFingerprint(r.sshKey),
			format.EncodeToString(ourPublicKey.Bytes()[:])},
	}
	// this tweak does key distancing using the ssh public key
	// it does not add any extra security, but kept it here
	// for backwards compatibility
	tweak := make([]byte, curve25519.ScalarSize)
	tH := hkdf.New(sha512.New, nil, r.sshKey.Marshal(), []byte(ed25519Label))
	if _, err := io.ReadFull(tH, tweak); err != nil {
		return nil, err
	}
	sharedSecret, _ = curve25519.X25519(tweak, sharedSecret)

	salt := make([]byte, 0, len(ourPublicKey.Bytes())+len(r.k.Bytes()))
	salt = append(salt, ourPublicKey.Bytes()...)
	salt = append(salt, r.k.Bytes()...)
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

	return []*age.Stanza{l}, nil
}

type Ed25519Identity struct {
	secretKey *ecdh.PrivateKey
	sshKey    ssh.PublicKey
}

var _ age.Identity = &Ed25519Identity{}

func NewEd25519Identity(key ed25519.PrivateKey) (*Ed25519Identity, error) {
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.X25519().NewPrivateKey(ed25519PrivateKeyToCurve25519(key))
	if err != nil {
		return nil, err
	}
	i := &Ed25519Identity{
		sshKey:    s.PublicKey(),
		secretKey: pk,
	}
	return i, nil
}

type ECDSAIdentity struct {
	secretKey *ecdh.PrivateKey
	sshKey    ssh.PublicKey
}

var _ age.Identity = &ECDSAIdentity{}

func NewECDSAIdentity(key *ecdsa.PrivateKey) (*ECDSAIdentity, error) {
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	pk, err := key.ECDH()
	if err != nil {
		return nil, err
	}
	i := &ECDSAIdentity{
		sshKey:    s.PublicKey(),
		secretKey: pk,
	}
	return i, nil
}

func (i *ECDSAIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *ECDSAIdentity) unwrap(block *age.Stanza) ([]byte, error) {
	if block.Type != "ecdsa-sha2-nistp256" && block.Type != "ecdsa-sha2-nistp384" && block.Type != "ecdsa-sha2-nistp521" {
		return nil, age.ErrIncorrectIdentity
	}
	if len(block.Args) != 2 {
		return nil, errors.New("invalid ecdsa recipient block")
	}
	publicKeyBytes, err := format.DecodeString(block.Args[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ecdsa recipient: %v", err)
	}

	publicKey, err := i.secretKey.Curve().NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, errors.New("invalid ecdsa recipient block")
	}

	if block.Args[0] != sshFingerprint(i.sshKey) {
		return nil, age.ErrIncorrectIdentity
	}
	sharedSecret, err := i.secretKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid ecdsa recipient: %v", err)
	}

	salt := make([]byte, 0, len(publicKey.Bytes())+len(i.secretKey.PublicKey().Bytes()))
	salt = append(salt, publicKey.Bytes()...)
	salt = append(salt, i.secretKey.PublicKey().Bytes()...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(labelForEcdsaCurve(i.secretKey.Curve())))
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

func (i *ECDSAIdentity) Recipient() *ECDSARecipient {
	return &ECDSARecipient{
		sshKey: i.sshKey,
		k:      i.secretKey.PublicKey(),
	}
}

func ParseIdentity(pemBytes []byte) (age.Identity, error) {
	k, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	switch k := k.(type) {
	case *ed25519.PrivateKey:
		return NewEd25519Identity(*k)
	// ParseRawPrivateKey returns inconsistent types. See Issue 429.
	case ed25519.PrivateKey:
		return NewEd25519Identity(k)
	case *rsa.PrivateKey:
		return NewRSAIdentity(k)
	case *ecdsa.PrivateKey:
		return NewECDSAIdentity(k)
	}

	return nil, fmt.Errorf("unsupported SSH identity type: %T", k)
}

func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) []byte {
	h := sha512.New()
	h.Write(pk.Seed())
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
}

func (i *Ed25519Identity) Recipient() *Ed25519Recipient {
	return &Ed25519Recipient{
		sshKey: i.sshKey,
		k:      i.secretKey.PublicKey(),
	}
}

func (i *Ed25519Identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *Ed25519Identity) unwrap(block *age.Stanza) ([]byte, error) {
	if block.Type != "ssh-ed25519" {
		return nil, age.ErrIncorrectIdentity
	}
	if len(block.Args) != 2 {
		return nil, errors.New("invalid ssh-ed25519 recipient block")
	}
	publicKeyBytes, err := format.DecodeString(block.Args[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh-ed25519 recipient: %v", err)
	}

	publicKey, err := ecdh.X25519().NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, errors.New("invalid ssh-ed25519 recipient block")
	}

	if block.Args[0] != sshFingerprint(i.sshKey) {
		return nil, age.ErrIncorrectIdentity
	}

	// .ECDH does the same as curve25519.X25519(ephemeral, theirPublicKey)
	sharedSecret, err := i.secretKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 recipient: %v", err)
	}

	// this tweak does key distancing using the ssh public key
	// it does not add any extra security, but kept it here
	// for backwards compatibility
	tweak := make([]byte, curve25519.ScalarSize)
	tH := hkdf.New(sha512.New, nil, i.sshKey.Marshal(), []byte(ed25519Label))
	if _, err := io.ReadFull(tH, tweak); err != nil {
		return nil, err
	}
	sharedSecret, _ = curve25519.X25519(tweak, sharedSecret)

	salt := make([]byte, 0, len(publicKey.Bytes())+len(i.secretKey.PublicKey().Bytes()))
	salt = append(salt, publicKey.Bytes()...)
	salt = append(salt, i.secretKey.PublicKey().Bytes()...)
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

// multiUnwrap is copied from package age. It's a helper that implements
// Identity.Unwrap in terms of a function that unwraps a single recipient
// stanza.
func multiUnwrap(unwrap func(*age.Stanza) ([]byte, error), stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		fileKey, err := unwrap(s)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			// If we ever start returning something interesting wrapping
			// ErrIncorrectIdentity, we should let it make its way up through
			// Decrypt into NoIdentityMatchError.Errors.
			continue
		}
		if err != nil {
			return nil, err
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

// aeadEncrypt and aeadDecrypt are copied from package age.
//
// They don't limit the file key size because multi-key attacks are irrelevant
// against the ssh-ed25519 recipient. Being an asymmetric recipient, it would
// only allow a more efficient search for accepted public keys against a
// decryption oracle, but the ssh-X recipients are not anonymous (they have a
// short recipient hash).

func aeadEncrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func aeadDecrypt(key, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Open(nil, nonce, ciphertext, nil)
}
