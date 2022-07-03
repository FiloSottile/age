// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package armor_test

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/internal/format"
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
	t.Run("PartialLine", func(t *testing.T) { testArmor(t, 611) })
	t.Run("FullLine", func(t *testing.T) { testArmor(t, 10*format.BytesPerLine) })
}

func testArmor(t *testing.T, size int) {
	buf := &bytes.Buffer{}
	w := armor.NewWriter(buf)
	plain := make([]byte, size)
	rand.Read(plain)
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
	if len(block.Headers) != 0 {
		t.Error("unexpected headers")
	}
	if block.Type != "AGE ENCRYPTED FILE" {
		t.Errorf("unexpected type %q", block.Type)
	}
	if !bytes.Equal(block.Bytes, plain) {
		t.Error("PEM decoded value doesn't match")
	}
	if !bytes.Equal(buf.Bytes(), pem.EncodeToMemory(block)) {
		t.Error("PEM re-encoded value doesn't match")
	}

	r := armor.NewReader(buf)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Error("decoded value doesn't match")
	}
}

func FuzzMalleability(f *testing.F) {
	tests, err := filepath.Glob("../testdata/testkit/*")
	if err != nil {
		f.Fatal(err)
	}
	for _, test := range tests {
		contents, err := os.ReadFile(test)
		if err != nil {
			f.Fatal(err)
		}
		header, contents, ok := bytes.Cut(contents, []byte("\n\n"))
		if !ok {
			f.Fatal("testkit file without header")
		}
		if bytes.Contains(header, []byte("armored: yes")) {
			f.Add(contents)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := armor.NewReader(bytes.NewReader(data))
		content, err := io.ReadAll(r)
		if err != nil {
			if _, ok := err.(*armor.Error); !ok {
				t.Errorf("error type is %T: %v", err, err)
			}
			t.Skip()
		}
		buf := &bytes.Buffer{}
		w := armor.NewWriter(buf)
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(normalize(buf.Bytes()), normalize(data)) {
			t.Error("re-encoded output different from input")
		}
	})
}

func normalize(f []byte) []byte {
	f = bytes.TrimSpace(f)
	f = bytes.Replace(f, []byte("\r\n"), []byte("\n"), -1)
	return f
}
