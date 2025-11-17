// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"filippo.io/age"
)

func TestX25519RoundTrip(t *testing.T) {
	i, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r := i.Recipient()

	if r1, err := age.ParseX25519Recipient(r.String()); err != nil {
		t.Fatal(err)
	} else if r1.String() != r.String() {
		t.Errorf("recipient did not round-trip through parsing: got %q, want %q", r1, r)
	}
	if i1, err := age.ParseX25519Identity(i.String()); err != nil {
		t.Fatal(err)
	} else if i1.String() != i.String() {
		t.Errorf("identity did not round-trip through parsing: got %q, want %q", i1, i)
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}
	stanzas, err := r.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	out, err := i.Unwrap(stanzas)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fileKey, out) {
		t.Errorf("invalid output: %x, expected %x", out, fileKey)
	}
}

func TestHybridRoundTrip(t *testing.T) {
	i, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r := i.Recipient()

	if r1, err := age.ParseHybridRecipient(r.String()); err != nil {
		t.Fatal(err)
	} else if r1.String() != r.String() {
		t.Errorf("recipient did not round-trip through parsing: got %q, want %q", r1, r)
	}
	if i1, err := age.ParseHybridIdentity(i.String()); err != nil {
		t.Fatal(err)
	} else if i1.String() != i.String() {
		t.Errorf("identity did not round-trip through parsing: got %q, want %q", i1, i)
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}
	stanzas, err := r.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	out, err := i.Unwrap(stanzas)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fileKey, out) {
		t.Errorf("invalid output: %x, expected %x", out, fileKey)
	}
}

func TestHybridMixingRestrictions(t *testing.T) {
	x25519, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// Hybrid recipients can be used together.
	if _, err := age.Encrypt(io.Discard, hybrid.Recipient(), hybrid.Recipient()); err != nil {
		t.Errorf("expected two hybrid recipients to work, got %v", err)
	}

	// Hybrid and X25519 recipients cannot be mixed.
	if _, err := age.Encrypt(io.Discard, hybrid.Recipient(), x25519.Recipient()); err == nil {
		t.Error("expected hybrid mixed with X25519 to fail")
	}
	if _, err := age.Encrypt(io.Discard, x25519.Recipient(), hybrid.Recipient()); err == nil {
		t.Error("expected X25519 mixed with hybrid to fail")
	}
}

func TestScryptRoundTrip(t *testing.T) {
	password := "twitch.tv/filosottile"

	r, err := age.NewScryptRecipient(password)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(15)
	i, err := age.NewScryptIdentity(password)
	if err != nil {
		t.Fatal(err)
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}
	stanzas, err := r.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	out, err := i.Unwrap(stanzas)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fileKey, out) {
		t.Errorf("invalid output: %x, expected %x", out, fileKey)
	}
}
