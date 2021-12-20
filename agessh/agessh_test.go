// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agessh_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

func TestSSHRSARoundTrip(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&pk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	r, err := agessh.NewRSARecipient(pub)
	if err != nil {
		t.Fatal(err)
	}
	i, err := agessh.NewRSAIdentity(pk)
	if err != nil {
		t.Fatal(err)
	}

	// TODO: replace this with (and go-diff) with go-cmp.
	if !reflect.DeepEqual(r, i.Recipient()) {
		t.Fatalf("i.Recipient is different from r")
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

func TestSSHEd25519RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	r, err := agessh.NewEd25519Recipient(sshPubKey)
	if err != nil {
		t.Fatal(err)
	}
	i, err := agessh.NewEd25519Identity(priv)
	if err != nil {
		t.Fatal(err)
	}

	// TODO: replace this with (and go-diff) with go-cmp.
	if !reflect.DeepEqual(r, i.Recipient()) {
		t.Fatalf("i.Recipient is different from r")
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
