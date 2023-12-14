// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

func ExampleEncrypt() {
	publicKey := "age1cy0su9fwf3gf9mw868g5yut09p6nytfmmnktexz2ya5uqg9vl9sss4euqm"
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		log.Fatalf("Failed to parse public key %q: %v", publicKey, err)
	}

	out := &bytes.Buffer{}

	w, err := age.Encrypt(out, recipient)
	if err != nil {
		log.Fatalf("Failed to create encrypted file: %v", err)
	}
	if _, err := io.WriteString(w, "Black lives matter."); err != nil {
		log.Fatalf("Failed to write to encrypted file: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Failed to close encrypted file: %v", err)
	}

	fmt.Printf("Encrypted file size: %d\n", out.Len())
	// Output:
	// Encrypted file size: 219
}

// DO NOT hardcode the private key. Store it in a secret storage solution,
// on disk if the local machine is trusted, or have the user provide it.
var privateKey string

func init() {
	privateKey = "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU"
}

func ExampleDecrypt() {
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	f, err := os.Open("testdata/example.age")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	r, err := age.Decrypt(f, identity)
	if err != nil {
		log.Fatalf("Failed to open encrypted file: %v", err)
	}
	out := &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		log.Fatalf("Failed to read encrypted file: %v", err)
	}

	fmt.Printf("File contents: %q\n", out.Bytes())
	// Output:
	// File contents: "Black lives matter."
}

func ExampleParseIdentities() {
	keyFile, err := os.Open("testdata/example_keys.txt")
	if err != nil {
		log.Fatalf("Failed to open private keys file: %v", err)
	}
	identities, err := age.ParseIdentities(keyFile)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	f, err := os.Open("testdata/example.age")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	r, err := age.Decrypt(f, identities...)
	if err != nil {
		log.Fatalf("Failed to open encrypted file: %v", err)
	}
	out := &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		log.Fatalf("Failed to read encrypted file: %v", err)
	}

	fmt.Printf("File contents: %q\n", out.Bytes())
	// Output:
	// File contents: "Black lives matter."
}

func ExampleGenerateX25519Identity() {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	fmt.Printf("Public key: %s...\n", identity.Recipient().String()[:4])
	fmt.Printf("Private key: %s...\n", identity.String()[:16])
	// Output:
	// Public key: age1...
	// Private key: AGE-SECRET-KEY-1...
}

const helloWorld = "Hello, Twitch!"

func TestEncryptDecryptX25519(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, a.Recipient(), b.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, helloWorld); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := age.Decrypt(buf, b)
	if err != nil {
		t.Fatal(err)
	}
	outBytes, err := io.ReadAll(out)
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
	outBytes, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(outBytes) != helloWorld {
		t.Errorf("wrong data: %q, excepted %q", outBytes, helloWorld)
	}
}

func TestParseIdentities(t *testing.T) {
	tests := []struct {
		name      string
		wantCount int
		wantErr   bool
		file      string
	}{
		{"valid", 2, false, `
# this is a comment
# AGE-SECRET-KEY-1705XN76M8EYQ8M9PY4E2G3KA8DN7NSCGT3V4HMN20H3GCX4AS6HSSTG8D3
#

AGE-SECRET-KEY-1D6K0SGAX3NU66R4GYFZY0UQWCLM3UUSF3CXLW4KXZM342WQSJ82QKU59QJ
AGE-SECRET-KEY-19WUMFE89H3928FRJ5U3JYRNHM6CERQGKSQ584AQ8QY7T7R09D32SWE4DYH`},
		{"invalid", 0, true, `
AGE-SECRET-KEY-1705XN76M8EYQ8M9PY4E2G3KA8DN7NSCGT3V4HMN20H3GCX4AS6HSSTG8D3
AGE-SECRET-KEY--1D6K0SGAX3NU66R4GYFZY0UQWCLM3UUSF3CXLW4KXZM342WQSJ82QKU59Q`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := age.ParseIdentities(strings.NewReader(tt.file))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIdentities() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantCount {
				t.Errorf("ParseIdentities() returned %d identities, want %d", len(got), tt.wantCount)
			}
		})
	}
}

type testRecipient struct {
	labels []string
}

func (testRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	panic("expected WrapWithLabels instead")
}

func (t testRecipient) WrapWithLabels(fileKey []byte) (s []*age.Stanza, labels []string, err error) {
	return []*age.Stanza{{Type: "test"}}, t.labels, nil
}

func TestLabels(t *testing.T) {
	scrypt, err := age.NewScryptRecipient("xxx")
	if err != nil {
		t.Fatal(err)
	}
	i, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	x25519 := i.Recipient()
	pqc := testRecipient{[]string{"postquantum"}}
	pqcAndFoo := testRecipient{[]string{"postquantum", "foo"}}
	fooAndPQC := testRecipient{[]string{"foo", "postquantum"}}

	if _, err := age.Encrypt(io.Discard, scrypt, scrypt); err == nil {
		t.Error("expected two scrypt recipients to fail")
	}
	if _, err := age.Encrypt(io.Discard, scrypt, x25519); err == nil {
		t.Error("expected x25519 mixed with scrypt to fail")
	}
	if _, err := age.Encrypt(io.Discard, x25519, scrypt); err == nil {
		t.Error("expected x25519 mixed with scrypt to fail")
	}
	if _, err := age.Encrypt(io.Discard, pqc, x25519); err == nil {
		t.Error("expected x25519 mixed with pqc to fail")
	}
	if _, err := age.Encrypt(io.Discard, x25519, pqc); err == nil {
		t.Error("expected x25519 mixed with pqc to fail")
	}
	if _, err := age.Encrypt(io.Discard, pqc, pqc); err != nil {
		t.Errorf("expected two pqc to work, got %v", err)
	}
	if _, err := age.Encrypt(io.Discard, pqc); err != nil {
		t.Errorf("expected one pqc to work, got %v", err)
	}
	if _, err := age.Encrypt(io.Discard, pqcAndFoo, pqc); err == nil {
		t.Error("expected pqc+foo mixed with pqc to fail")
	}
	if _, err := age.Encrypt(io.Discard, pqc, pqcAndFoo); err == nil {
		t.Error("expected pqc+foo mixed with pqc to fail")
	}
	if _, err := age.Encrypt(io.Discard, pqc, pqc, pqcAndFoo); err == nil {
		t.Error("expected pqc+foo mixed with pqc to fail")
	}
	if _, err := age.Encrypt(io.Discard, pqcAndFoo, pqcAndFoo); err != nil {
		t.Errorf("expected two pqc+foo to work, got %v", err)
	}
	if _, err := age.Encrypt(io.Discard, pqcAndFoo, fooAndPQC); err != nil {
		t.Errorf("expected pqc+foo mixed with foo+pqc to work, got %v", err)
	}
}
