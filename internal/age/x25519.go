// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package age

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const x25519Label = "age-encryption.org/v1/X25519"

type X25519Recipient struct {
	theirPublicKey []byte
}

var _ Recipient = &X25519Recipient{}

func (*X25519Recipient) Type() string { return "X25519" }

func NewX25519Recipient(publicKey []byte) (*X25519Recipient, error) {
	if len(publicKey) != curve25519.PointSize {
		return nil, errors.New("invalid X25519 public key")
	}
	r := &X25519Recipient{
		theirPublicKey: make([]byte, curve25519.PointSize),
	}
	copy(r.theirPublicKey, publicKey)
	return r, nil
}

func ParseX25519Recipient(s string) (*X25519Recipient, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "age" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}
	r, err := NewX25519Recipient(k)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	return r, nil
}

func (r *X25519Recipient) Wrap(fileKey []byte) (*format.Recipient, error) {
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

	l := &format.Recipient{
		Type: "X25519",
		Args: []string{format.EncodeToString(ourPublicKey)},
	}

	salt := make([]byte, 0, len(ourPublicKey)+len(r.theirPublicKey))
	salt = append(salt, ourPublicKey...)
	salt = append(salt, r.theirPublicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(x25519Label))
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

func (r *X25519Recipient) String() string {
	s, _ := bech32.Encode("age", r.theirPublicKey)
	return s
}

type X25519Identity struct {
	secretKey, ourPublicKey []byte
}

var _ Identity = &X25519Identity{}

func (*X25519Identity) Type() string { return "X25519" }

func NewX25519Identity(secretKey []byte) (*X25519Identity, error) {
	if len(secretKey) != curve25519.ScalarSize {
		return nil, errors.New("invalid X25519 secret key")
	}
	i := &X25519Identity{
		secretKey: make([]byte, curve25519.ScalarSize),
	}
	copy(i.secretKey, secretKey)
	i.ourPublicKey, _ = curve25519.X25519(i.secretKey, curve25519.Basepoint)
	return i, nil
}

func GenerateX25519Identity() (*X25519Identity, error) {
	secretKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(secretKey); err != nil {
		return nil, fmt.Errorf("internal error: %v", err)
	}
	return NewX25519Identity(secretKey)
}

func ParseX25519Identity(s string) (*X25519Identity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key %q: %v", s, err)
	}
	if t != "AGE-SECRET-KEY-" {
		return nil, fmt.Errorf("malformed secret key %q: invalid type %q", s, t)
	}
	r, err := NewX25519Identity(k)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key %q: %v", s, err)
	}
	return r, nil
}

func (i *X25519Identity) Unwrap(block *format.Recipient) ([]byte, error) {
	if block.Type != "X25519" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid X25519 recipient block")
	}
	publicKey, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X25519 recipient: %v", err)
	}
	if len(publicKey) != curve25519.PointSize {
		return nil, errors.New("invalid X25519 recipient block")
	}

	sharedSecret, err := curve25519.X25519(i.secretKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 recipient: %v", err)
	}

	salt := make([]byte, 0, len(publicKey)+len(i.ourPublicKey))
	salt = append(salt, publicKey...)
	salt = append(salt, i.ourPublicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(x25519Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	fileKey, err := aeadDecrypt(wrappingKey, block.Body)
	if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}

func (i *X25519Identity) Recipient() *X25519Recipient {
	r := &X25519Recipient{}
	r.theirPublicKey = i.ourPublicKey
	return r
}

func (i *X25519Identity) String() string {
	s, _ := bech32.Encode("AGE-SECRET-KEY-", i.secretKey)
	return strings.ToUpper(s)
}
