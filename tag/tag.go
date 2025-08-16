// Copyright 2025 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tag

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/internal/format"
	"filippo.io/age/plugin"
	"filippo.io/age/tag/internal/hpke"
	"filippo.io/nistec"
)

type Recipient struct {
	kem hpke.KEMSender

	compressed   [33]byte
	uncompressed [65]byte
}

var _ age.Recipient = &Recipient{}

// ParseRecipient returns a new [Recipient] from a Bech32 public key
// encoding with the "age1tag1" prefix.
func ParseRecipient(s string) (*Recipient, error) {
	t, k, err := plugin.ParseRecipient(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "tag" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}
	r, err := NewRecipient(k)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	return r, nil
}

// NewRecipient returns a new [Recipient] from a raw public key.
func NewRecipient(publicKey []byte) (*Recipient, error) {
	if len(publicKey) != 1+32 {
		return nil, fmt.Errorf("invalid tag recipient public key size %d", len(publicKey))
	}
	p, err := nistec.NewP256Point().SetBytes(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid tag recipient public key: %v", err)
	}
	k, err := ecdh.P256().NewPublicKey(p.Bytes())
	if err != nil {
		return nil, fmt.Errorf("invalid tag recipient public key: %v", err)
	}
	kem, err := hpke.DHKEMSender(k)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHKEM sender: %v", err)
	}
	r := &Recipient{kem: kem}
	copy(r.compressed[:], publicKey)
	copy(r.uncompressed[:], p.Bytes())
	return r, nil
}

var p256TagLabel = []byte("age-encryption.org/p256tag")

func (r *Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	enc, s, err := hpke.SetupSender(r.kem,
		hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(),
		p256TagLabel)
	if err != nil {
		return nil, fmt.Errorf("failed to set up HPKE sender: %v", err)
	}
	ct, err := s.Seal(nil, fileKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt file key: %v", err)
	}

	tag, err := hkdf.Extract(sha256.New, append(enc, r.uncompressed[:]...), p256TagLabel)
	if err != nil {
		return nil, fmt.Errorf("failed to compute tag: %v", err)
	}

	l := &age.Stanza{
		Type: "p256tag",
		Args: []string{
			format.EncodeToString(tag[:4]),
			format.EncodeToString(enc),
		},
		Body: ct,
	}

	return []*age.Stanza{l}, nil
}

// String returns the Bech32 public key encoding of r.
func (r *Recipient) String() string {
	return plugin.EncodeRecipient("tag", r.compressed[:])
}
