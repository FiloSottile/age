// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

//go:generate go test -generate -run ^$

func TestMain(m *testing.M) {
	genFlag := flag.Bool("generate", false, "regenerate test files")
	flag.Parse()
	if *genFlag {
		generators, err := filepath.Glob("testdata/*.go")
		if err != nil {
			log.Fatal(err)
		}
		for _, generator := range generators {
			vector := strings.TrimSuffix(generator, ".go") + ".test"
			fmt.Fprintf(os.Stderr, "%s -> %s\n", generator, vector)
			out, err := exec.Command("go", "run", generator).Output()
			if err != nil {
				log.Fatal(err)
			}
			os.WriteFile(vector, out, 0664)
		}
	}

	os.Exit(m.Run())
}

func TestVectors(t *testing.T) {
	tests, err := filepath.Glob("testdata/*.test")
	if err != nil {
		log.Fatal(err)
	}
	for _, test := range tests {
		contents, err := os.ReadFile(test)
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(test, "testdata/")
		name = strings.TrimSuffix(name, ".test")
		t.Run(name, func(t *testing.T) {
			testVector(t, contents)
		})
	}
}

func testVector(t *testing.T, test []byte) {
	var (
		expectHeaderFailure  bool
		expectPayloadFailure bool
		payloadHash          *[32]byte
		identities           []age.Identity
	)

	for {
		line, rest, ok := bytes.Cut(test, []byte("\n"))
		if !ok {
			t.Fatal("invalid test file: no payload")
		}
		test = rest
		if len(line) == 0 {
			break
		}
		key, value, _ := strings.Cut(string(line), ": ")
		switch key {
		case "expect":
			switch value {
			case "success":
			case "header failure":
				expectHeaderFailure = true
			case "payload failure":
				expectPayloadFailure = true
			default:
				t.Fatal("invalid test file: unknown expect value:", value)
			}
		case "payload":
			h, err := hex.DecodeString(value)
			if err != nil {
				t.Fatal(err)
			}
			payloadHash = (*[32]byte)(h)
		case "identity":
			i, err := age.ParseX25519Identity(value)
			if err != nil {
				t.Fatal(err)
			}
			identities = append(identities, i)
		case "comment":
			t.Log(value)
		default:
			t.Fatal("invalid test file: unknown header key:", key)
		}
	}

	r, err := age.Decrypt(bytes.NewReader(test), identities...)
	if err != nil {
		if expectHeaderFailure {
			return
		}
		t.Fatal("unexpected header error:", err)
	} else if expectHeaderFailure {
		t.Fatal("expected header error")
	}
	out, err := io.ReadAll(r)
	if err != nil {
		if expectPayloadFailure {
			return
		}
		t.Fatal("unexpected payload error:", err)
	} else if expectPayloadFailure {
		t.Fatal("expected payload error")
	}
	if sha256.Sum256(out) != *payloadHash {
		t.Error("payload hash mismatch")
	}
}
