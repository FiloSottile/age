// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package age_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"filippo.io/age"
	"filippo.io/age/internal/format"
)

func TestX25519RoundTrip(t *testing.T) {
	i, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r := i.Recipient()

	if r.Type() != i.Type() || r.Type() != "X25519" {
		t.Errorf("invalid Type values: %v, %v", r.Type(), i.Type())
	}

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
	block, err := r.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	b := &bytes.Buffer{}
	(*format.Stanza)(block).Marshal(b)
	t.Logf("%s", b.Bytes())

	out, err := i.Unwrap(block)
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

	if r.Type() != i.Type() || r.Type() != "scrypt" {
		t.Errorf("invalid Type values: %v, %v", r.Type(), i.Type())
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}
	block, err := r.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	b := &bytes.Buffer{}
	(*format.Stanza)(block).Marshal(b)
	t.Logf("%s", b.Bytes())

	out, err := i.Unwrap(block)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fileKey, out) {
		t.Errorf("invalid output: %x, expected %x", out, fileKey)
	}
}
