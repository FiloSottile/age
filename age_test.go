// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package age_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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

var fileContents, _ = hex.DecodeString("6167652d656e6372797074696f6e2e6f72" +
	"672f76310a2d3e20583235353139203868726c4d2b5a4247334464346646322b61353" +
	"8337a64544957446b382f5234316b43595a7376775457340a794f345059646c4d5744" +
	"4a2b437867554e527159355a30542f6d2b6733464368356a4978474c62435658630a2" +
	"d2d2d20492f696d65765a7a79383132304a537a6d4a6e6d6e2f4b4d6b337035413131" +
	"5638334e6b34316d394e50450a70c5e53624a1520753f92c5ad10ecab273ba4d61178" +
	"07713e83820417a1df2ca08182272c8f85c857734a1311a3b75e98d0eaf")

var privateKey = "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU"

func ExampleDecrypt() {
	// DO NOT hardcode the private key. Store it in a secret storage solution,
	// on disk if the local machine is trusted, or have the user provide it.
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key %q: %v", privateKey, err)
	}

	out := &bytes.Buffer{}
	f := bytes.NewReader(fileContents)

	r, err := age.Decrypt(f, identity)
	if err != nil {
		log.Fatalf("Failed to open encrypted file: %v", err)
	}
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
