// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package age_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/internal/format"
	"filippo.io/age/internal/stream"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	agetest "c2sp.org/CCTV/age"
)

func forEachVector(t *testing.T, f func(t *testing.T, v *vector)) {
	tests, err := fs.ReadDir(agetest.Vectors, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		name := test.Name()
		contents, err := fs.ReadFile(agetest.Vectors, name)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f(t, parseVector(t, contents))
		})
	}
}

type vector struct {
	expect      string
	payloadHash *[32]byte
	fileKey     *[16]byte
	identities  []age.Identity
	armored     bool
	file        []byte
}

func parseVector(t *testing.T, test []byte) *vector {
	v := &vector{file: test}
	for {
		line, rest, ok := bytes.Cut(v.file, []byte("\n"))
		if !ok {
			t.Fatal("invalid test file: no payload")
		}
		v.file = rest
		if len(line) == 0 {
			break
		}
		key, value, _ := strings.Cut(string(line), ": ")
		switch key {
		case "expect":
			switch value {
			case "success":
			case "HMAC failure":
			case "header failure":
			case "armor failure":
			case "payload failure":
			case "no match":
			default:
				t.Fatal("invalid test file: unknown expect value:", value)
			}
			v.expect = value
		case "payload":
			h, err := hex.DecodeString(value)
			if err != nil {
				t.Fatal(err)
			}
			v.payloadHash = (*[32]byte)(h)
		case "file key":
			h, err := hex.DecodeString(value)
			if err != nil {
				t.Fatal(err)
			}
			v.fileKey = (*[16]byte)(h)
		case "identity":
			i, err := age.ParseX25519Identity(value)
			if err != nil {
				t.Fatal(err)
			}
			v.identities = append(v.identities, i)
		case "passphrase":
			i, err := age.NewScryptIdentity(value)
			if err != nil {
				t.Fatal(err)
			}
			v.identities = append(v.identities, i)
		case "armored":
			v.armored = true
		case "comment":
			t.Log(value)
		default:
			t.Fatal("invalid test file: unknown header key:", key)
		}
	}
	return v
}

func TestVectors(t *testing.T) {
	forEachVector(t, testVector)
}

func testVector(t *testing.T, v *vector) {
	var in io.Reader = bytes.NewReader(v.file)
	if v.armored {
		in = armor.NewReader(in)
	}
	r, err := age.Decrypt(in, v.identities...)
	if err != nil && strings.HasSuffix(err.Error(), "bad header MAC") {
		if v.expect == "HMAC failure" {
			t.Log(err)
			return
		}
		t.Fatalf("expected %s, got HMAC error", v.expect)
	} else if e := new(armor.Error); errors.As(err, &e) {
		if v.expect == "armor failure" {
			t.Log(err)
			return
		}
		t.Fatalf("expected %s, got: %v", v.expect, err)
	} else if _, ok := err.(*age.NoIdentityMatchError); ok {
		if v.expect == "no match" {
			t.Log(err)
			return
		}
		t.Fatalf("expected %s, got: %v", v.expect, err)
	} else if err != nil {
		if v.expect == "header failure" {
			t.Log(err)
			return
		}
		t.Fatalf("expected %s, got: %v", v.expect, err)
	} else if v.expect != "success" && v.expect != "payload failure" &&
		v.expect != "armor failure" {
		t.Fatalf("expected %s, got success", v.expect)
	}
	out, err := io.ReadAll(r)
	if err != nil && v.expect == "success" {
		t.Fatalf("expected %s, got: %v", v.expect, err)
	} else if err != nil {
		t.Log(err)
		if v.expect == "armor failure" {
			if e := new(armor.Error); !errors.As(err, &e) {
				t.Errorf("expected armor.Error, got %T", err)
			}
		}
		if v.payloadHash != nil && sha256.Sum256(out) != *v.payloadHash {
			t.Error("partial payload hash mismatch")
		}
		return
	} else if v.expect != "success" {
		t.Fatalf("expected %s, got success", v.expect)
	}
	if sha256.Sum256(out) != *v.payloadHash {
		t.Error("payload hash mismatch")
	}
}

// TestVectorsRoundTrip checks that any (valid) armor, header, and/or STREAM
// payload in the test vectors re-encodes identically.
func TestVectorsRoundTrip(t *testing.T) {
	forEachVector(t, testVectorRoundTrip)
}

func testVectorRoundTrip(t *testing.T, v *vector) {
	if v.armored {
		if v.expect == "armor failure" {
			t.SkipNow()
		}
		t.Run("armor", func(t *testing.T) {
			payload, err := io.ReadAll(armor.NewReader(bytes.NewReader(v.file)))
			if err != nil {
				t.Fatal(err)
			}
			buf := &bytes.Buffer{}
			w := armor.NewWriter(buf)
			if _, err := w.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			// Armor format is not perfectly strict: CRLF ↔ LF and trailing and
			// leading spaces are allowed and won't round-trip.
			expect := bytes.Replace(v.file, []byte("\r\n"), []byte("\n"), -1)
			expect = bytes.TrimSpace(expect)
			expect = append(expect, '\n')
			if !bytes.Equal(buf.Bytes(), expect) {
				t.Error("got a different armor encoding")
			}
		})
		// Armor tests are not interesting beyond their armor encoding.
		return
	}

	if v.expect == "header failure" {
		t.SkipNow()
	}
	hdr, p, err := format.Parse(bytes.NewReader(v.file))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(p)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("header", func(t *testing.T) {
		buf := &bytes.Buffer{}
		if err := hdr.Marshal(buf); err != nil {
			t.Fatal(err)
		}
		buf.Write(payload)
		if !bytes.Equal(buf.Bytes(), v.file) {
			t.Error("got a different header+payload encoding")
		}
	})

	if v.expect == "success" {
		t.Run("STREAM", func(t *testing.T) {
			nonce, payload := payload[:16], payload[16:]
			key := streamKey(v.fileKey[:], nonce)
			r, err := stream.NewReader(key, bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			buf := &bytes.Buffer{}
			w, err := stream.NewWriter(key, buf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(plaintext); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf.Bytes(), payload) {
				t.Error("got a different STREAM ciphertext")
			}
		})
	}
}

func streamKey(fileKey, nonce []byte) []byte {
	h := hkdf.New(sha256.New, fileKey, nonce, []byte("payload"))
	streamKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, streamKey); err != nil {
		panic("age: internal error: failed to read from HKDF: " + err.Error())
	}
	return streamKey
}
