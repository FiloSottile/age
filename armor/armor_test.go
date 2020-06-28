// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package armor_test

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func ExampleNewWriter() {
	publicKey := "age1cy0su9fwf3gf9mw868g5yut09p6nytfmmnktexz2ya5uqg9vl9sss4euqm"
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		log.Fatalf("Failed to parse public key %q: %v", publicKey, err)
	}

	buf := &bytes.Buffer{}
	armorWriter := armor.NewWriter(buf)

	w, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		log.Fatalf("Failed to create encrypted file: %v", err)
	}
	if _, err := io.WriteString(w, "Black lives matter."); err != nil {
		log.Fatalf("Failed to write to encrypted file: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Failed to close encrypted file: %v", err)
	}

	if err := armorWriter.Close(); err != nil {
		log.Fatalf("Failed to close armor: %v", err)
	}

	fmt.Printf("%s[...]", buf.Bytes()[:35])
	// Output:
	// -----BEGIN AGE ENCRYPTED FILE-----
	// [...]
}

var privateKey = "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU"

func ExampleNewReader() {
	fileContents := `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4YWdhZHZ0WG1PZldDT1hD
K3RPRzFkUlJnWlFBQlUwemtjeXFRMFp6V1VFCnRzZFV3a3Vkd1dSUWw2eEtrRkVv
SHcvZnp6Q3lqLy9HMkM4ZjUyUGdDZjQKLS0tIDlpVUpuVUQ5YUJyUENFZ0lNSTB2
ekUvS3E5WjVUN0F5ZWR1ejhpeU5rZUUKsvPGYt7vf0o1kyJ1eVFMz1e4JnYYk1y1
kB/RRusYjn+KVJ+KTioxj0THtzZPXcjFKuQ1
-----END AGE ENCRYPTED FILE-----`

	// DO NOT hardcode the private key. Store it in a secret storage solution,
	// on disk if the local machine is trusted, or have the user provide it.
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key %q: %v", privateKey, err)
	}

	out := &bytes.Buffer{}
	f := strings.NewReader(fileContents)
	armorReader := armor.NewReader(f)

	r, err := age.Decrypt(armorReader, identity)
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

func TestArmor(t *testing.T) {
	buf := &bytes.Buffer{}
	w := armor.NewWriter(buf)
	plain := make([]byte, 611)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		t.Fatal("PEM decoding failed")
	}
	if !bytes.Equal(block.Bytes, plain) {
		t.Error("PEM decoded value doesn't match")
	}

	r := armor.NewReader(buf)
	out, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Error("decoded value doesn't match")
	}
}
