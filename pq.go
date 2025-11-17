// Copyright 2025 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"errors"
	"fmt"
	"strings"

	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/format"
	"filippo.io/hpke"
	"golang.org/x/crypto/chacha20poly1305"
)

const pqLabel = "age-encryption.org/mlkem768x25519"

// HybridRecipient is the standard age public key. Messages encrypted to
// this recipient can be decrypted with the corresponding [HybridIdentity].
//
// This recipient is safe against future cryptographically-relevant quantum
// computers, and can only be used along with other post-quantum recipients.
//
// This recipient is anonymous, in the sense that an attacker can't tell from
// the message alone if it is encrypted to a certain recipient.
type HybridRecipient struct {
	pk hpke.PublicKey
}

var _ Recipient = &HybridRecipient{}

// newHybridRecipient returns a new [HybridRecipient] from a raw HPKE public key.
func newHybridRecipient(publicKey []byte) (*HybridRecipient, error) {
	pk, err := hpke.MLKEM768X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, errors.New("invalid MLKEM768-X25519 public key")
	}
	return &HybridRecipient{pk: pk}, nil
}

// ParseHybridRecipient returns a new [HybridRecipient] from a Bech32 public key
// encoding with the "age1pq1" prefix.
func ParseHybridRecipient(s string) (*HybridRecipient, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "age1pq" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}
	r, err := newHybridRecipient(k)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	return r, nil
}

func (r *HybridRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	s, _, err := r.WrapWithLabels(fileKey)
	return s, err
}

// WrapWithLabels implements [RecipientWithLabels], returning a single
// "postquantum" label. This ensures a HybridRecipient can't be mixed with other
// recipients that would defeat its post-quantum security.
//
// To unsafely bypass this restriction, wrap HybridRecipient in a [Recipient]
// type that doesn't expose WrapWithLabels.
func (r *HybridRecipient) WrapWithLabels(fileKey []byte) ([]*Stanza, []string, error) {
	enc, s, err := hpke.NewSender(r.pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(pqLabel))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set up HPKE sender: %v", err)
	}
	ct, err := s.Seal(nil, fileKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt file key: %v", err)
	}

	l := &Stanza{
		Type: "mlkem768x25519",
		Args: []string{format.EncodeToString(enc)},
		Body: ct,
	}

	return []*Stanza{l}, []string{"postquantum"}, nil
}

// String returns the Bech32 public key encoding of r.
func (r *HybridRecipient) String() string {
	s, _ := bech32.Encode("age1pq", r.pk.Bytes())
	return s
}

// HybridIdentity is the standard age private key, which can decrypt messages
// encrypted to the corresponding [HybridRecipient].
type HybridIdentity struct {
	k hpke.PrivateKey
}

var _ Identity = &HybridIdentity{}

// newHybridIdentity returns a new [HybridIdentity] from a raw HPKE private key.
func newHybridIdentity(secretKey []byte) (*HybridIdentity, error) {
	k, err := hpke.MLKEM768X25519().NewPrivateKey(secretKey)
	if err != nil {
		return nil, errors.New("invalid MLKEM768-X25519 secret key")
	}
	return &HybridIdentity{k: k}, nil
}

// GenerateHybridIdentity randomly generates a new [HybridIdentity].
func GenerateHybridIdentity() (*HybridIdentity, error) {
	k, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate post-quantum identity: %v", err)
	}
	return &HybridIdentity{k: k}, nil
}

// ParseHybridIdentity returns a new [HybridIdentity] from a Bech32 private key
// encoding with the "AGE-SECRET-KEY-PQ-1" prefix.
func ParseHybridIdentity(s string) (*HybridIdentity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-SECRET-KEY-PQ-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}
	r, err := newHybridIdentity(k)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	return r, nil
}

func (i *HybridIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *HybridIdentity) unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "mlkem768x25519" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid mlkem768x25519 recipient block")
	}
	enc, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse mlkem768x25519 recipient: %v", err)
	}
	if len(block.Body) != fileKeySize+chacha20poly1305.Overhead {
		return nil, errIncorrectCiphertextSize
	}

	r, err := hpke.NewRecipient(enc, i.k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(pqLabel))
	if err != nil {
		// MLKEM768-X25519 does implicit rejection, so a mismatched key does not
		// hit this error path, but is only detected later when trying to open.
		return nil, fmt.Errorf("invalid mlkem768x25519 recipient: %v", err)
	}
	fileKey, err := r.Open(nil, block.Body)
	if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}

// Recipient returns the public [HybridRecipient] value corresponding to i.
func (i *HybridIdentity) Recipient() *HybridRecipient {
	return &HybridRecipient{pk: i.k.PublicKey()}
}

// String returns the Bech32 private key encoding of i.
func (i *HybridIdentity) String() string {
	b, _ := i.k.Bytes()
	s, _ := bech32.Encode("AGE-SECRET-KEY-PQ-", b)
	return strings.ToUpper(s)
}
