// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/cloudflare/circl/kem/hybrid"
)

const (
	x25519Kyber768Label = "age-encryption.org/v1/x25519Kyber768"
	// TODO add Version
	prefexPublicKey = "agePQ."
	// TODO add Version
	prefixSecretKey = "AGE-PQ-SECRET-KEY-"
)

// x25519Kyber768Recipient is the PQ age public key. Messages encrypted to this
// recipient can be decrypted with the corresponding x25519Kyber768Identity.
//
// This recipient is anonymous, in the sense that an attacker can't tell from
// the message alone if it is encrypted to a certain recipient.
type x25519Kyber768Recipient struct {
	theirPublicKey []byte
}

var _ Recipient = &x25519Kyber768Recipient{}

// newx25519Kyber768RecipientFromPoint returns a new x25519Kyber768Recipient from a hybrid (classical/quantum) key encapsulation mechanism (KEM).
func newx25519Kyber768RecipientFromPoint(publicKey []byte) (*x25519Kyber768Recipient, error) {
	if len(publicKey) != kem.PublicKeySize() {
		return nil, errors.New("invalid x25519Kyber768 public key")
	}
	r := &x25519Kyber768Recipient{
		theirPublicKey: make([]byte, kem.PublicKeySize()),
	}
	copy(r.theirPublicKey, publicKey)
	return r, nil
}

// Parsex25519Kyber768Recipient returns a new x25519Kyber768Recipient from a Base64 public key
// encoding with the "agePQ." prefix.
func Parsex25519Kyber768Recipient(s string) (*x25519Kyber768Recipient, error) {
	if !strings.HasPrefix(s, prefexPublicKey) {
		return nil, fmt.Errorf("malformed recipient missing prefix %v", prefexPublicKey)
	}

	s = strings.TrimLeft(s, prefexPublicKey)

	k, err := format.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}

	r, err := newx25519Kyber768RecipientFromPoint(k)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	return r, nil
}

// Wrap encapsulate (encrypt) cryptographic key material
func (r *x25519Kyber768Recipient) Wrap(fileKey []byte) ([]*Stanza, error) {

	pub, err := kem.UnmarshalBinaryPublicKey(r.theirPublicKey)
	if err != nil {
		return nil, err
	}
	ct, ss, err := kem.Encapsulate(pub)
	if err != nil {
		return nil, err
	}

	l := &Stanza{
		Type: "x25519Kyber768",
		Args: []string{format.EncodeToString(ct)},
	}

	salt := make([]byte, 0, len(r.theirPublicKey))
	salt = append(salt, r.theirPublicKey...)
	h := hkdf.New(sha256.New, ss, salt, []byte(x25519Kyber768Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return []*Stanza{l}, nil
}

// String returns the Baee64 public key encoding of r.
func (r *x25519Kyber768Recipient) String() string {
	s := prefexPublicKey + format.EncodeToString(r.theirPublicKey)
	return s
}

// X25519Kyber768Identity is the standard age private key, which can decrypt messages
// encrypted to the corresponding x25519Kyber768Recipient.
type X25519Kyber768Identity struct {
	secretKey, ourPublicKey []byte
	// TODO Maybe hold the kem.PrivateKey directly for better performance
}

var _ Identity = &X25519Kyber768Identity{}

var kem = hybrid.Kyber768X25519()

// newx25519Kyber768IdentityFromScalar returns a new x25519Kyber768Identity derived from a secret key.
func newx25519Kyber768IdentityFromScalar(secretKey []byte) (*X25519Kyber768Identity, error) {
	if len(secretKey) != kem.SeedSize() {
		return nil, errors.New("invalid x25519Kyber768 secret key")
	}

	pub, _ := kem.DeriveKeyPair(secretKey)

	i := &X25519Kyber768Identity{
		secretKey: make([]byte, kem.SeedSize()),
	}
	copy(i.secretKey, secretKey)
	i.ourPublicKey, _ = pub.MarshalBinary()
	return i, nil
}

// Generatex25519Kyber768Identity randomly generates a new x25519Kyber768Identity.
func Generatex25519Kyber768Identity() (*X25519Kyber768Identity, error) {
	secretKey := make([]byte, kem.SeedSize())
	if _, err := rand.Read(secretKey); err != nil {
		return nil, fmt.Errorf("internal error: %v", err)
	}
	return newx25519Kyber768IdentityFromScalar(secretKey)
}

// Parsex25519Kyber768Identity returns a new x25519Kyber768Identity from a Base64 private key
// encoding with the "AGE-PQ-SECRET-KEY" prefix.
func Parsex25519Kyber768Identity(s string) (*X25519Kyber768Identity, error) {
	if !strings.HasPrefix(s, prefixSecretKey) {
		return nil, fmt.Errorf("malformed secret key: prefix %v missing", prefixSecretKey)
	}

	s = strings.TrimPrefix(s, prefixSecretKey)

	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	r, err := newx25519Kyber768IdentityFromScalar(data)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	return r, nil
}

func (i *X25519Kyber768Identity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *X25519Kyber768Identity) unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "x25519Kyber768" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid x25519Kyber768 recipient block")
	}
	ct, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse x25519Kyber768 recipient: %v", err)
	}

	_, myPrivateKey := kem.DeriveKeyPair(i.secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to UnmarshalBinaryPrivateKey: %v", err)
	}
	sharedSecret, err := kem.Decapsulate(myPrivateKey, ct)
	if err != nil {
		return nil, fmt.Errorf("failed to Decapsulate: %v", err)
	}

	salt := make([]byte, 0, len(i.ourPublicKey))
	// TODO add more entropy? salt = append(salt, publicKey...)
	salt = append(salt, i.ourPublicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(x25519Kyber768Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	fileKey, err := aeadDecrypt(wrappingKey, fileKeySize, block.Body)
	if err == errIncorrectCiphertextSize {
		return nil, errors.New("invalid x25519Kyber768 recipient block: incorrect file key size")
	} else if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}

// Recipient returns the public x25519Kyber768Recipient value corresponding to i.
func (i *X25519Kyber768Identity) Recipient() *x25519Kyber768Recipient {
	r := &x25519Kyber768Recipient{}
	r.theirPublicKey = i.ourPublicKey
	return r
}

// String returns the Base64 private key encoding of i.
func (i *X25519Kyber768Identity) String() string {
	// TODO Base64 best format?
	return prefixSecretKey + base64.StdEncoding.EncodeToString(i.secretKey)
}
