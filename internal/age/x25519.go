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

	"github.com/FiloSottile/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	x25519Label   = "age-tool.com X25519"
	x25519KeySize = 32
)

type X25519Recipient struct {
	theirPublicKey [x25519KeySize]byte
}

var _ Recipient = &X25519Recipient{}

func (*X25519Recipient) Type() string { return "X25519" }

func NewX25519Recipient(publicKey []byte) (*X25519Recipient, error) {
	if len(publicKey) != x25519KeySize {
		return nil, errors.New("invalid X25519 public key")
	}
	r := &X25519Recipient{}
	copy(r.theirPublicKey[:], publicKey)
	return r, nil
}

func ParseX25519Recipient(s string) (*X25519Recipient, error) {
	if !strings.HasPrefix(s, "pubkey:") {
		return nil, fmt.Errorf("malformed recipient: %s", s)
	}
	pubKey := strings.TrimPrefix(s, "pubkey:")
	k, err := format.DecodeString(pubKey)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient: %s", s)
	}
	r, err := NewX25519Recipient(k)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient: %s", s)
	}
	return r, nil
}

func (r *X25519Recipient) Wrap(fileKey []byte) (*format.Recipient, error) {
	var ephemeral, ourPublicKey [x25519KeySize]byte
	if _, err := rand.Read(ephemeral[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&ourPublicKey, &ephemeral)

	var sharedSecret [x25519KeySize]byte
	curve25519.ScalarMult(&sharedSecret, &ephemeral, &r.theirPublicKey)

	l := &format.Recipient{
		Type: "X25519",
		Args: []string{format.EncodeToString(ourPublicKey[:])},
	}

	salt := make([]byte, 0, x25519KeySize*2)
	salt = append(salt, ourPublicKey[:]...)
	salt = append(salt, r.theirPublicKey[:]...)
	h := hkdf.New(sha256.New, sharedSecret[:], salt, []byte(x25519Label))
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

func (r *X25519Recipient) String() string {
	return "pubkey:" + format.EncodeToString(r.theirPublicKey[:])
}

type X25519Identity struct {
	secretKey, ourPublicKey [x25519KeySize]byte
}

var _ Identity = &X25519Identity{}

func (*X25519Identity) Type() string { return "X25519" }

func NewX25519Identity(secretKey []byte) (*X25519Identity, error) {
	if len(secretKey) != x25519KeySize {
		return nil, errors.New("invalid X25519 secret key")
	}
	i := &X25519Identity{}
	copy(i.secretKey[:], secretKey)
	curve25519.ScalarBaseMult(&i.ourPublicKey, &i.secretKey)
	return i, nil
}

func ParseX25519Identity(s string) (*X25519Identity, error) {
	if !strings.HasPrefix(s, "AGE_SECRET_KEY_") {
		return nil, fmt.Errorf("malformed secret key: %s", s)
	}
	privKey := strings.TrimPrefix(s, "AGE_SECRET_KEY_")
	k, err := format.DecodeString(privKey)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %s", s)
	}
	r, err := NewX25519Identity(k)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %s", s)
	}
	return r, nil
}

func (i *X25519Identity) Unwrap(block *format.Recipient) ([]byte, error) {
	if block.Type != "X25519" {
		return nil, errors.New("wrong recipient block type")
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid X25519 recipient block")
	}
	publicKey, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X25519 recipient: %v", err)
	}
	if len(publicKey) != x25519KeySize {
		return nil, errors.New("invalid X25519 recipient block")
	}
	wrappedKey, err := format.DecodeString(string(block.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse X25519 recipient: %v", err)
	}

	var sharedSecret, theirPublicKey [x25519KeySize]byte
	copy(theirPublicKey[:], publicKey)
	curve25519.ScalarMult(&sharedSecret, &i.secretKey, &theirPublicKey)

	salt := make([]byte, 0, x25519KeySize*2)
	salt = append(salt, theirPublicKey[:]...)
	salt = append(salt, i.ourPublicKey[:]...)
	h := hkdf.New(sha256.New, sharedSecret[:], salt, []byte(x25519Label))
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

func (i *X25519Identity) Recipient() *X25519Recipient {
	r := &X25519Recipient{}
	r.theirPublicKey = i.ourPublicKey
	return r
}

func (i *X25519Identity) String() string {
	return "AGE_SECRET_KEY_" + format.EncodeToString(i.secretKey[:])
}
