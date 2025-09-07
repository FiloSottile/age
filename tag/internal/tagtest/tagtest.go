// Copyright 2025 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tagtest

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"testing"

	"filippo.io/age"
	"filippo.io/age/internal/format"
	"filippo.io/age/tag"
	"filippo.io/hpke"
	"filippo.io/nistec"
)

type ClassicIdentity struct {
	t *testing.T
	k hpke.PrivateKey
}

var _ age.Identity = &ClassicIdentity{}

func NewClassicIdentity(t *testing.T) *ClassicIdentity {
	k, err := hpke.DHKEM(ecdh.P256()).GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return &ClassicIdentity{k: k}
}

func (i *ClassicIdentity) Recipient() *tag.Recipient {
	uncompressed := i.k.PublicKey().Bytes()
	p, err := nistec.NewP256Point().SetBytes(uncompressed)
	if err != nil {
		i.t.Fatalf("failed to parse public key: %v", err)
	}
	r, err := tag.NewClassicRecipient(p.BytesCompressed())
	if err != nil {
		i.t.Fatalf("failed to create recipient: %v", err)
	}
	return r
}

func (i *ClassicIdentity) Unwrap(ss []*age.Stanza) ([]byte, error) {
	for _, s := range ss {
		if s.Type != "p256tag" {
			continue
		}
		if len(s.Args) != 2 {
			return nil, fmt.Errorf("malformed stanza")
		}
		tagArg, err := format.DecodeString(s.Args[0])
		if err != nil {
			return nil, fmt.Errorf("malformed tag: %v", err)
		}
		if len(tagArg) != 4 {
			return nil, fmt.Errorf("invalid tag length: %d", len(tagArg))
		}
		enc, err := format.DecodeString(s.Args[1])
		if err != nil {
			return nil, fmt.Errorf("malformed encapsulated key: %v", err)
		}
		if len(enc) != 65 {
			return nil, fmt.Errorf("invalid encapsulated key length: %d", len(enc))
		}
		if len(s.Body) != 32 {
			return nil, fmt.Errorf("invalid encrypted file key length: %d", len(s.Body))
		}

		expTag, err := hkdf.Extract(sha256.New, append(enc, i.k.PublicKey().Bytes()...), []byte("age-encryption.org/p256tag"))
		if err != nil {
			return nil, fmt.Errorf("failed to compute tag: %v", err)
		}
		if subtle.ConstantTimeCompare(tagArg, expTag[:4]) != 1 {
			return nil, age.ErrIncorrectIdentity
		}

		r, err := hpke.NewRecipient(enc, i.k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("age-encryption.org/p256tag"))
		if err != nil {
			return nil, fmt.Errorf("failed to unwrap file key: %v", err)
		}
		return r.Open(nil, s.Body)
	}
	return nil, age.ErrIncorrectIdentity
}

type HybridIdentity struct {
	t *testing.T
	k hpke.PrivateKey
}

var _ age.Identity = &HybridIdentity{}

func NewHybridIdentity(t *testing.T) *HybridIdentity {
	k, err := hpke.MLKEM768P256().GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return &HybridIdentity{k: k}
}

func (i *HybridIdentity) Recipient() *tag.Recipient {
	r, err := tag.NewHybridRecipient(i.k.PublicKey().Bytes())
	if err != nil {
		i.t.Fatalf("failed to create recipient: %v", err)
	}
	return r
}

func (i *HybridIdentity) Unwrap(ss []*age.Stanza) ([]byte, error) {
	for _, s := range ss {
		if s.Type != "mlkem768p256tag" {
			continue
		}
		if len(s.Args) != 2 {
			return nil, fmt.Errorf("malformed stanza")
		}
		tagArg, err := format.DecodeString(s.Args[0])
		if err != nil {
			return nil, fmt.Errorf("malformed tag: %v", err)
		}
		if len(tagArg) != 4 {
			return nil, fmt.Errorf("invalid tag length: %d", len(tagArg))
		}
		enc, err := format.DecodeString(s.Args[1])
		if err != nil {
			return nil, fmt.Errorf("malformed encapsulated key: %v", err)
		}
		if len(enc) != 1153 {
			return nil, fmt.Errorf("invalid encapsulated key length: %d", len(enc))
		}
		if len(s.Body) != 32 {
			return nil, fmt.Errorf("invalid encrypted file key length: %d", len(s.Body))
		}

		expTag, err := hkdf.Extract(sha256.New, append(enc[1088:], i.k.PublicKey().Bytes()[1184:]...), []byte("age-encryption.org/mlkem768p256tag"))
		if err != nil {
			return nil, fmt.Errorf("failed to compute tag: %v", err)
		}
		if subtle.ConstantTimeCompare(tagArg, expTag[:4]) != 1 {
			return nil, age.ErrIncorrectIdentity
		}

		r, err := hpke.NewRecipient(enc, i.k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("age-encryption.org/mlkem768p256tag"))
		if err != nil {
			return nil, fmt.Errorf("failed to unwrap file key: %v", err)
		}
		return r.Open(nil, s.Body)
	}
	return nil, age.ErrIncorrectIdentity
}
