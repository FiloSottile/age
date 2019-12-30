// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package age_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"testing"

	"filippo.io/age/internal/age"
	"golang.org/x/crypto/curve25519"
)

const helloWorld = "Hello, Twitch!"

func TestEncryptDecryptX25519(t *testing.T) {
	secretKeyA := make([]byte, curve25519.ScalarSize)
	secretKeyB := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(secretKeyA); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(secretKeyB); err != nil {
		t.Fatal(err)
	}
	publicKeyA, _ := curve25519.X25519(secretKeyA, curve25519.Basepoint)
	publicKeyB, _ := curve25519.X25519(secretKeyB, curve25519.Basepoint)

	rA, err := age.NewX25519Recipient(publicKeyA)
	if err != nil {
		t.Fatal(err)
	}
	rB, err := age.NewX25519Recipient(publicKeyB)
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, rA, rB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, helloWorld); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	i, err := age.NewX25519Identity(secretKeyB)
	if err != nil {
		t.Fatal(err)
	}
	out, err := age.Decrypt(buf, i)
	if err != nil {
		t.Fatal(err)
	}
	outBytes, err := ioutil.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(outBytes) != helloWorld {
		t.Errorf("wrong data: %q, excepted %q", outBytes, helloWorld)
	}
}

func TestEncryptDecryptScrypt(t *testing.T) {
	password := "twitch.tv/filosottile"

	r, err := age.NewScryptRecipient(password)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(15)
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, helloWorld); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	i, err := age.NewScryptIdentity(password)
	if err != nil {
		t.Fatal(err)
	}
	out, err := age.Decrypt(buf, i)
	if err != nil {
		t.Fatal(err)
	}
	outBytes, err := ioutil.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(outBytes) != helloWorld {
		t.Errorf("wrong data: %q, excepted %q", outBytes, helloWorld)
	}
}
