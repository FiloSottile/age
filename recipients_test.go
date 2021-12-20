// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age_test

import (
	"bytes"
	"crypto/rand"
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
