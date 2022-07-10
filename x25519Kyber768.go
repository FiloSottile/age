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

const x25519Kyber768Label = "age-encryption.org/v1/x25519Kyber768"

// x25519Kyber768Recipient is the standard age public key. Messages encrypted to this
// recipient can be decrypted with the corresponding x25519Kyber768Identity.
//
// This recipient is anonymous, in the sense that an attacker can't tell from
// the message alone if it is encrypted to a certain recipient.
type x25519Kyber768Recipient struct {
	theirPublicKey []byte
}

var _ Recipient = &x25519Kyber768Recipient{}

// newx25519Kyber768RecipientFromPoint returns a new x25519Kyber768Recipient from a raw Curve25519 point.
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

// Parsex25519Kyber768Recipient returns a new x25519Kyber768Recipient from a Bech32 public key
// encoding with the "age1" prefix.
func Parsex25519Kyber768Recipient(s string) (*x25519Kyber768Recipient, error) {
	if !strings.HasPrefix(s, publicKeyIdenerty) {
		return nil, fmt.Errorf("malformed recipient missing prefix %v", publicKeyIdenerty)
	}

	s = strings.TrimLeft(s, publicKeyIdenerty)

	k, err := format.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	// if t != "age" {
	// 	return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	// }
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

	fmt.Printf("aeadEncrypt: key: %x\n pt: %x\n", wrappingKey, fileKey)
	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey
	fmt.Printf("aeadEncrypt: ct: %x\n", wrappedKey)

	return []*Stanza{l}, nil
}

const publicKeyIdenerty = "agePQ."

// String returns the Bech32 public key encoding of r.
// 👷‍♂️
func (r *x25519Kyber768Recipient) String() string {
	// TODO Prefix
	// s, _ := bech32.Encode("age", r.theirPublicKey)
	s := publicKeyIdenerty + format.EncodeToString(r.theirPublicKey)
	return s
}

// x25519Kyber768Identity is the standard age private key, which can decrypt messages
// encrypted to the corresponding x25519Kyber768Recipient.
type x25519Kyber768Identity struct {
	secretKey, ourPublicKey []byte
	// TODO
	NO_NEED_ourPrivateKey []byte
}

var _ Identity = &x25519Kyber768Identity{}

var kem = hybrid.Kyber768X25519()

// newx25519Kyber768IdentityFromScalar returns a new x25519Kyber768Identity from a raw Curve25519 scalar.
// 👷‍♂️
func newx25519Kyber768IdentityFromScalar(secretKey []byte) (*x25519Kyber768Identity, error) {
	if len(secretKey) != kem.SeedSize() {
		return nil, errors.New("invalid x25519Kyber768 secret key")
	}

	pub, priv := kem.DeriveKeyPair(secretKey)

	i := &x25519Kyber768Identity{
		secretKey: make([]byte, kem.SeedSize()),
	}
	copy(i.secretKey, secretKey)
	i.ourPublicKey, _ = pub.MarshalBinary()
	i.NO_NEED_ourPrivateKey, _ = priv.MarshalBinary()
	return i, nil
}

// Generatex25519Kyber768Identity randomly generates a new x25519Kyber768Identity.
func Generatex25519Kyber768Identity() (*x25519Kyber768Identity, error) {
	secretKey := make([]byte, kem.SeedSize())
	if _, err := rand.Read(secretKey); err != nil {
		return nil, fmt.Errorf("internal error: %v", err)
	}
	return newx25519Kyber768IdentityFromScalar(secretKey)
}

// Parsex25519Kyber768Identity returns a new x25519Kyber768Identity from a Bech32 private key
// encoding with the "AGE-SECRET-KEY-1" prefix.
// 👷‍♂️
func Parsex25519Kyber768Identity(s string) (*x25519Kyber768Identity, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	// TODO add prefix
	// if t != "AGE-SECRET-KEY-" {
	// 	return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	// }
	r, err := newx25519Kyber768IdentityFromScalar(data)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	return r, nil
}

func (i *x25519Kyber768Identity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *x25519Kyber768Identity) unwrap(block *Stanza) ([]byte, error) {
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
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to parse x25519Kyber768 recipient: %v", err)
	// }
	// if len(publicKey) != curve25519.PointSize {
	// 	return nil, errors.New("invalid x25519Kyber768 recipient block")
	// }

	// sharedSecret, err := curve25519.x25519Kyber768(i.secretKey, publicKey)
	// if err != nil {
	// 	return nil, fmt.Errorf("invalid x25519Kyber768 recipient: %v", err)
	// }

	_, myPrivateKey := kem.DeriveKeyPair(i.secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to UnmarshalBinaryPrivateKey: %v", err)
	}
	sharedSecret, err := kem.Decapsulate(myPrivateKey, ct)
	if err != nil {
		return nil, fmt.Errorf("failed to Decapsulate: %v", err)
	}

	salt := make([]byte, 0, len(i.ourPublicKey))
	// salt = append(salt, publicKey...)
	salt = append(salt, i.ourPublicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(x25519Kyber768Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	fmt.Printf("aeadDecrypt: key: %x\n size: %v ct: %x\n", wrappingKey, fileKeySize, block.Body)
	fileKey, err := aeadDecrypt(wrappingKey, fileKeySize, block.Body)
	if err == errIncorrectCiphertextSize {
		return nil, errors.New("invalid x25519Kyber768 recipient block: incorrect file key size")
	} else if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}

// Recipient returns the public x25519Kyber768Recipient value corresponding to i.
func (i *x25519Kyber768Identity) Recipient() *x25519Kyber768Recipient {
	r := &x25519Kyber768Recipient{}
	r.theirPublicKey = i.ourPublicKey
	return r
}

// String returns the Bech32 private key encoding of i.
// 👷‍♂️
func (i *x25519Kyber768Identity) String() string {
	// TODO add prefix
	// s, _ := bech32.Encode("AGE-SECRET-KEY-", i.secretKey)
	return base64.StdEncoding.EncodeToString(i.secretKey)
}
