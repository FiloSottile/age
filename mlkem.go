// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"crypto/sha256"
	"crypto/mlkem"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const mlkemLabel = "age-encryption.org/v1/mlkem"

// MLKEMRecipient is the standard age public key. Messages encrypted to this
// recipient can be decrypted with the corresponding MLKEMIdentity.
//
// This recipient is anonymous, in the sense that an attacker can't tell from
// the message alone if it is encrypted to a certain recipient.
type MLKEMRecipient struct {
	theirPublicKey []byte
}

var _ Recipient = &MLKEMRecipient{}

// newMLKEMRecipientFromPoint returns a new MLKEMRecipient from a raw Curve25519 point.
func newMLKEMRecipientFromPublicKey(publicKey []byte) (*MLKEMRecipient, error) {
	if len(publicKey) != mlkem.EncapsulationKeySize768 {
		return nil, errors.New("invalid MLKEM public key")
	}
	r := &MLKEMRecipient{
		theirPublicKey: make([]byte, mlkem.EncapsulationKeySize768),
	}
	copy(r.theirPublicKey, publicKey)
	return r, nil
}

// ParseMLKEMRecipient returns a new MLKEMRecipient from a Bech32 public key
// encoding with the "age1" prefix.
func ParseMLKEMRecipient(s string) (*MLKEMRecipient, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "age" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}
	r, err := newMLKEMRecipientFromPublicKey(k)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	return r, nil
}

func (r *MLKEMRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	theirEncapKey, err := mlkem.NewEncapsulationKey768(r.theirPublicKey)
	if err != nil {
		return nil, err
	}

	sharedSecret, ciphertext := theirEncapKey.Encapsulate()
	
	l := &Stanza{
		Type: "MLKEM",
		Args: []string{format.EncodeToString(ciphertext)},
	}

	salt := make([]byte, 0, len(ciphertext)+len(r.theirPublicKey))
	salt = append(salt, ciphertext...)
	salt = append(salt, r.theirPublicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(mlkemLabel))
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

// String returns the Bech32 public key encoding of r.
func (r *MLKEMRecipient) String() string {
	s, _ := bech32.Encode("age", r.theirPublicKey)
	return s
}

// MLKEMIdentity is the standard age private key, which can decrypt messages
// encrypted to the corresponding MLKEMRecipient.
type MLKEMIdentity struct {
	privateKey, ourPublicKey []byte
}

var _ Identity = &MLKEMIdentity{}

// newMLKEMIdentityFromSeed returns a new MLKEMIdentity from a raw 
// ML-KEM encapsulation key.
func newMLKEMIdentityFromSeed(privateKey []byte) (*MLKEMIdentity, error) {
	if len(privateKey) != mlkem.SeedSize {
		return nil, errors.New("invalid MLKEM private key")
	}
	i := &MLKEMIdentity{
		privateKey: make([]byte, mlkem.SeedSize),
	}
	copy(i.privateKey, privateKey)
	
	ourPrivateKey, err := mlkem.NewDecapsulationKey768(i.privateKey)
	if err != nil {
		return nil, fmt.Errorf("internal error: %v", err)
	}

	i.ourPublicKey = ourPrivateKey.EncapsulationKey().Bytes()
	return i, nil
}

// GenerateMLKEMIdentity randomly generates a new MLKEMIdentity.
func GenerateMLKEMIdentity() (*MLKEMIdentity, error) {
	privateKey := make([]byte, mlkem.SeedSize)

	decapKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("internal error: %v", err)
	}
	copy(privateKey, decapKey.Bytes())

	return newMLKEMIdentityFromSeed(privateKey)
}

// ParseMLKEMIdentity returns a new MLKEMIdentity from a Bech32 private key
// encoding with the "AGE-SECRET-KEY-1" prefix.
func ParseMLKEMIdentity(s string) (*MLKEMIdentity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-SECRET-KEY-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}
	r, err := newMLKEMIdentityFromSeed(k)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	return r, nil
}

func (i *MLKEMIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *MLKEMIdentity) unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "MLKEM" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid MLKEM recipient block")
	}
	ciphertext, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse MLKEM recipient: %v", err)
	}
	if len(ciphertext) != mlkem.CiphertextSize768 {
		return nil, errors.New("invalid MLKEM recipient block")
	}

	ourDecapKey, err := mlkem.NewDecapsulationKey768(i.privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid MLKEM private key: %v", err)
	
	}

	sharedSecret, err := ourDecapKey.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid MLKEM recipient: %v", err)
	}

	salt := make([]byte, 0, len(ciphertext)+len(i.ourPublicKey))
	salt = append(salt, ciphertext...)
	salt = append(salt, i.ourPublicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(mlkemLabel))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	fileKey, err := aeadDecrypt(wrappingKey, fileKeySize, block.Body)
	if err == errIncorrectCiphertextSize {
		return nil, errors.New("invalid MLKEM recipient block: incorrect file key size")
	} else if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}

// Recipient returns the public MLKEMRecipient value corresponding to i.
func (i *MLKEMIdentity) Recipient() *MLKEMRecipient {
	r := &MLKEMRecipient{}
	r.theirPublicKey = i.ourPublicKey
	return r
}

// String returns the Bech32 private key encoding of i.
func (i *MLKEMIdentity) String() string {
	s, _ := bech32.Encode("AGE-SECRET-KEY-", i.privateKey)
	return strings.ToUpper(s)
}
