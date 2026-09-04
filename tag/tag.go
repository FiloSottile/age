// Copyright 2025 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tag implements tagged P-256/X25519 or hybrid P-256/X25519 + ML-KEM-768 recipients,
// which can be used with identities stored on hardware keys, usually supported
// by dedicated plugins.
//
// The tag reduces privacy, by allowing an observer to correlate files with a
// recipient (but not files amongst them without knowledge of the recipient),
// but this is also a desirable property for hardware keys that require user
// interaction for each decryption operation.
package tag

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"fmt"
	"slices"

	"filippo.io/age"
	"filippo.io/age/internal/format"
	"filippo.io/age/plugin"
	"filippo.io/hpke"
	"filippo.io/nistec"
	"golang.org/x/crypto/curve25519"
)

// Recipient is a tagged P-256/X25519 or hybrid P-256/X25519 + ML-KEM-768 recipient.
//
// The latter recipient is safe against future cryptographically-relevant
// quantum computers, and can only be used along with other post-quantum
// recipients.
type Recipient struct {
	pk hpke.PublicKey
}

var _ age.Recipient = &Recipient{}

// ParseRecipient returns a new [Recipient] from a Bech32 public key
// encoding with the "age1tag1" or "age1tagpq1" prefix.
func ParseRecipient(s string) (*Recipient, error) {
	t, k, err := plugin.ParseRecipient(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	switch t {
	case "tag":
		r, err := NewClassicRecipient(k)
		if err != nil {
			return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
		}
		return r, nil
	case "tagpq":
		r, err := NewHybridRecipient(k)
		if err != nil {
			return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
		}
		return r, nil
	default:
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}
}

const compressedPointSize = 1 + 32
const uncompressedPointSize = 1 + 32 + 32

// NewClassicRecipient returns a new P-256/X25519 [Recipient] from a raw public key.
func NewClassicRecipient(publicKey []byte) (*Recipient, error) {
	var k hpke.PublicKey
	var err error
	if len(publicKey) == curve25519.PointSize {
		k, err = hpke.DHKEM(ecdh.X25519()).NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid tag recipient public key: %v", err)
		}
	} else if len(publicKey) == compressedPointSize {
		p, err := nistec.NewP256Point().SetBytes(publicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid tag recipient public key: %v", err)
		}
		k, err = hpke.DHKEM(ecdh.P256()).NewPublicKey(p.Bytes())
		if err != nil {
			return nil, fmt.Errorf("invalid tag recipient public key: %v", err)
		}
	} else {
		return nil, fmt.Errorf("invalid tag recipient public key size %d", len(publicKey))
	}
	return &Recipient{k}, nil
}

// NewHybridRecipient returns a new hybrid P-256/X25519 + ML-KEM-768 [Recipient] from
// raw concatenated public keys.
func NewHybridRecipient(publicKey []byte) (*Recipient, error) {
	var k hpke.PublicKey
	var err error
	if len(publicKey) == 1216 {
		k, err = hpke.MLKEM768X25519().NewPublicKey(publicKey)
	} else {
		k, err = hpke.MLKEM768P256().NewPublicKey(publicKey)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid tagpq recipient public key: %v", err)
	}
	return &Recipient{k}, nil
}

// Hybrid reports whether r is a hybrid P-256/X25519 + ML-KEM-768 recipient.
func (r *Recipient) Hybrid() bool {
	hybridIds := []uint16{hpke.MLKEM768P256().ID(), hpke.MLKEM768X25519().ID()}
	return slices.Contains(hybridIds, r.pk.KEM().ID())
}

func (r *Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	s, _, err := r.WrapWithLabels(fileKey)
	return s, err
}

// Tag computes the 4-byte tag for the given ciphertext enc.
//
// This is a low-level method exposed for use by plugins that implement
// identities compatible with tagged recipients.
func (r *Recipient) Tag(enc []byte) ([]byte, error) {
	var label string
	tagRecipient := r.Bytes()
	if r.Hybrid() {
		switch r.pk.KEM().ID() {
		case hpke.MLKEM768P256().ID():
			label = "age-encryption.org/mlkem768p256tag"
			// In hybrid mode, the tag is computed over just the P-256 part.
			tagRecipient = tagRecipient[mlkem.EncapsulationKeySize768:]
			if len(enc) != mlkem.CiphertextSize768+uncompressedPointSize {
				return nil, fmt.Errorf("invalid ciphertext size")
			}
		case hpke.MLKEM768X25519().ID():
			label = "age-encryption.org/mlkem768x25519tag"
			// In hybrid mode, the tag is computed over just the X25519 part.
			tagRecipient = tagRecipient[mlkem.EncapsulationKeySize768:]
			if len(enc) != mlkem.CiphertextSize768+curve25519.PointSize {
				return nil, fmt.Errorf("invalid ciphertext size")
			}
		}
	} else if len(enc) == curve25519.PointSize {
		label = "age-encryption.org/x25519tag"
	} else if len(enc) == uncompressedPointSize {
		label = "age-encryption.org/p256tag"
	} else {
		return nil, fmt.Errorf("invalid ciphertext size")
	}
	rh := sha256.Sum256(tagRecipient)
	tag, err := hkdf.Extract(sha256.New, append(slices.Clip(enc), rh[:4]...), []byte(label))
	if err != nil {
		return nil, fmt.Errorf("failed to compute tag: %v", err)
	}
	return tag[:4], nil
}

// WrapWithLabels implements [age.RecipientWithLabels], returning a single
// "postquantum" label if r is a hybrid P-256/X25519 + ML-KEM-768 recipient. This
// ensures a hybrid Recipient can't be mixed with other recipients that would
// defeat its post-quantum security.
//
// To unsafely bypass this restriction, wrap Recipient in an [age.Recipient]
// type that doesn't expose WrapWithLabels.
func (r *Recipient) WrapWithLabels(fileKey []byte) ([]*age.Stanza, []string, error) {
	var label, arg string
	if r.Hybrid() {
		switch r.pk.KEM().ID() {
		case hpke.MLKEM768P256().ID():
			label, arg = "age-encryption.org/mlkem768p256tag", "mlkem768p256tag"
		case hpke.MLKEM768X25519().ID():
			label, arg = "age-encryption.org/mlkem768x25519tag", "mlkem768x25519tag"
		}
	} else if len(r.pk.Bytes()) == curve25519.PointSize {
		label, arg = "age-encryption.org/x25519tag", "x25519tag"
	} else {
		label, arg = "age-encryption.org/p256tag", "p256tag"
	}

	enc, s, err := hpke.NewSender(r.pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(label))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set up HPKE sender: %v", err)
	}
	ct, err := s.Seal(nil, fileKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt file key: %v", err)
	}

	tag, err := r.Tag(enc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute tag: %v", err)
	}

	l := &age.Stanza{
		Type: arg,
		Args: []string{
			format.EncodeToString(tag[:4]),
			format.EncodeToString(enc),
		},
		Body: ct,
	}

	if r.Hybrid() {
		return []*age.Stanza{l}, []string{"postquantum"}, nil
	}
	return []*age.Stanza{l}, nil, nil
}

// Bytes returns the raw recipient encoding.
func (r *Recipient) Bytes() []byte {
	if r.Hybrid() || len(r.pk.Bytes()) == curve25519.PointSize {
		return r.pk.Bytes()
	}
	p, err := nistec.NewP256Point().SetBytes(r.pk.Bytes())
	if err != nil {
		panic("internal error: invalid P-256 public key")
	}
	return p.BytesCompressed()
}

// String returns the Bech32 public key encoding of r.
func (r *Recipient) String() string {
	if r.Hybrid() {
		return plugin.EncodeRecipient("tagpq", r.Bytes())
	}
	return plugin.EncodeRecipient("tag", r.Bytes())
}
