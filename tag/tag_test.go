// Copyright 2025 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tag_test

import (
	"bytes"
	"io"
	"testing"

	"filippo.io/age"
	"filippo.io/age/tag"
	"filippo.io/age/tag/internal/tagtest"
)

func TestClassicRoundTrip(t *testing.T) {
	i := tagtest.NewClassicIdentity(t)
	r := i.Recipient()

	if r.Hybrid() {
		t.Error("classic recipient incorrectly reports as hybrid")
	}

	r1, err := tag.ParseRecipient(r.String())
	if err != nil {
		t.Fatal(err)
	}
	if r1.String() != r.String() {
		t.Errorf("recipient did not round-trip through parsing: got %q, want %q", r1.String(), r.String())
	}
	if r1.Hybrid() {
		t.Error("parsed classic recipient incorrectly reports as hybrid")
	}

	plaintext := []byte("hello world")

	encrypted := &bytes.Buffer{}
	w, err := age.Encrypt(encrypted, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	decrypted, err := age.Decrypt(encrypted, i)
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(decrypted)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, out) {
		t.Errorf("invalid output: %q, expected %q", out, plaintext)
	}
}

func TestHybridRoundTrip(t *testing.T) {
	i := tagtest.NewHybridIdentity(t)
	r := i.Recipient()

	if !r.Hybrid() {
		t.Error("hybrid recipient incorrectly reports as classic")
	}

	r1, err := tag.ParseRecipient(r.String())
	if err != nil {
		t.Fatal(err)
	}
	if r1.String() != r.String() {
		t.Errorf("recipient did not round-trip through parsing: got %q, want %q", r1.String(), r.String())
	}
	if !r1.Hybrid() {
		t.Error("parsed hybrid recipient incorrectly reports as classic")
	}

	plaintext := []byte("hello world")

	encrypted := &bytes.Buffer{}
	w, err := age.Encrypt(encrypted, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	decrypted, err := age.Decrypt(encrypted, i)
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(decrypted)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, out) {
		t.Errorf("invalid output: %q, expected %q", out, plaintext)
	}
}
