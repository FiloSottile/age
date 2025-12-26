// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18

package age_test

import (
	"bytes"
	"compress/zlib"
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
	"filippo.io/age/internal/inspect"
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
	var z bool
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
			var i age.Identity
			i, err := age.ParseX25519Identity(value)
			if err != nil {
				i, err = age.ParseHybridIdentity(value)
			}
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
		case "compressed":
			if value != "zlib" {
				t.Fatal("invalid test file: unknown compression:", value)
			}
			z = true
		case "comment":
			t.Log(value)
		default:
			t.Fatal("invalid test file: unknown header key:", key)
		}
	}
	if z {
		r, err := zlib.NewReader(bytes.NewReader(v.file))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		v.file = b
	}
	return v
}

func TestVectors(t *testing.T) {
	forEachVector(t, func(t *testing.T, v *vector) {
		var plaintext []byte
		t.Run("Decrypt", func(t *testing.T) { plaintext = testDecrypt(t, v) })
		t.Run("DecryptReaderAt", func(t *testing.T) { testDecryptReaderAt(t, v, plaintext) })
		t.Run("Inspect", func(t *testing.T) { testInspect(t, v, plaintext) })
		t.Run("RoundTrip", func(t *testing.T) { testVectorRoundTrip(t, v) })
	})
}

func testDecrypt(t *testing.T, v *vector) []byte {
	var in io.Reader = bytes.NewReader(v.file)
	if v.armored {
		in = armor.NewReader(in)
	}
	r, err := age.Decrypt(in, v.identities...)
	if err != nil && strings.HasSuffix(err.Error(), "bad header MAC") {
		if v.expect == "HMAC failure" {
			t.Log(err)
			return nil
		}
		t.Fatalf("expected %s, got HMAC error", v.expect)
	} else if e := new(armor.Error); errors.As(err, &e) {
		if v.expect == "armor failure" {
			t.Log(err)
			return nil
		}
		t.Fatalf("expected %s, got: %v", v.expect, err)
	} else if _, ok := err.(*age.NoIdentityMatchError); ok {
		if v.expect == "no match" {
			t.Log(err)
			return nil
		}
		t.Fatalf("expected %s, got: %v", v.expect, err)
	} else if err != nil {
		if v.expect == "header failure" {
			t.Log(err)
			return nil
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
			t.Errorf("partial payload hash mismatch, read %d bytes", len(out))
		}
		return out
	} else if v.expect != "success" {
		t.Fatalf("expected %s, got success", v.expect)
	}
	if sha256.Sum256(out) != *v.payloadHash {
		t.Error("payload hash mismatch")
	}
	return out
}

func testDecryptReaderAt(t *testing.T, v *vector, plaintext []byte) {
	if v.armored {
		t.Skip("armor.NewReader does not implement ReaderAt")
	}
	rAt, s, err := age.DecryptReaderAt(bytes.NewReader(v.file), int64(len(v.file)), v.identities...)
	switch v.expect {
	case "success":
		if err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
		if int64(len(plaintext)) != s {
			t.Errorf("unexpected size: got %d, want %d", s, len(plaintext))
		}
	case "payload failure":
		// DecryptReaderAt detects some (but not all) payload failures upfront,
		// either from the size of the payload, or by decrypting the last chunk
		// to authenticate its size.
		if err != nil {
			t.Log(err)
			return
		}
	default:
		if err != nil {
			t.Log(err)
			return
		}
		t.Fatalf("expected %s, got success", v.expect)
	}
	out, err := io.ReadAll(io.NewSectionReader(rAt, 0, s))
	if v.expect == "success" {
		if err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
	} else {
		if err == nil {
			t.Fatalf("expected %s, got success", v.expect)
		}
		t.Log(err)
		// We can't check the partial payload hash, because the ReaderAt will
		// notice errors that a linearly scanning Reader could not. For example,
		// if there are two final chunks, the linear Reader will decrypt the
		// first one and then error out on the second, while the ReaderAt will
		// decrypt the second one to check the size, and then know that the
		// first chunk could not be the last one. Instead, check that the
		// prefix, if any, matches.
		if !bytes.HasPrefix(plaintext, out) {
			t.Errorf("partial payload prefix mismatch, read %d bytes", len(out))
		}
		return
	}
	if sha256.Sum256(out) != *v.payloadHash {
		t.Error("payload hash mismatch")
	}
}

func testInspect(t *testing.T, v *vector, plaintext []byte) {
	if v.expect != "success" {
		t.Skip("invalid file, can't inspect")
	}
	for _, fileSize := range []int64{int64(len(v.file)), -1} {
		metadata, err := inspect.Inspect(bytes.NewReader(v.file), fileSize)
		if err != nil {
			t.Fatalf("inspect failed: %v", err)
		}
		if metadata.Armor != v.armored {
			t.Errorf("unexpected armor: %v", metadata.Armor)
		}
		if metadata.Armor && metadata.Sizes.Armor == 0 {
			t.Errorf("expected non-zero armor size")
		}
		if metadata.Sizes.Armor+metadata.Sizes.Header+metadata.Sizes.Overhead+metadata.Sizes.MinPayload != int64(len(v.file)) {
			t.Errorf("size breakdown does not add up to file size")
		}
		if metadata.Sizes.MinPayload != int64(len(plaintext)) {
			t.Errorf("unexpected payload size: got %d, want %d", metadata.Sizes.MinPayload, len(plaintext))
		}
		if metadata.Sizes.MaxPayload != metadata.Sizes.MinPayload {
			t.Errorf("unexpected max payload size: got %d, want %d", metadata.Sizes.MaxPayload, metadata.Sizes.MinPayload)
		}
		if metadata.Sizes.MinPadding != 0 || metadata.Sizes.MaxPadding != 0 {
			t.Errorf("unexpected padding sizes: got min %d max %d, want 0", metadata.Sizes.MinPadding, metadata.Sizes.MaxPadding)
		}
	}
}

// testVectorsRoundTrip checks that any (valid) armor, header, and/or STREAM
// payload in the test vectors re-encodes identically.
func testVectorRoundTrip(t *testing.T, v *vector) {
	if v.armored {
		if v.expect == "armor failure" {
			t.Skip("invalid armor, nothing to round-trip")
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
		t.Skip("invalid header, nothing to round-trip")
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

	if v.expect != "success" {
		return
	}

	t.Run("STREAM", func(t *testing.T) {
		nonce, payload := payload[:16], payload[16:]
		key := streamKey(v.fileKey[:], nonce)

		r, err := stream.NewDecryptReader(key, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}

		rAt, err := stream.NewDecryptReaderAt(key, bytes.NewReader(payload), int64(len(payload)))
		if err != nil {
			t.Fatal(err)
		}
		plaintextAt, err := io.ReadAll(io.NewSectionReader(rAt, 0, int64(len(plaintext))))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plaintextAt, plaintext) {
			t.Errorf("got a different plaintext from DecryptReaderAt")
		}

		buf := &bytes.Buffer{}
		w, err := stream.NewEncryptWriter(key, buf)
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

		er, err := stream.NewEncryptReader(key, bytes.NewReader(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		ciphertext, err := io.ReadAll(er)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ciphertext, payload) {
			t.Error("got a different STREAM ciphertext from EncryptReader")
		}
	})
}

func streamKey(fileKey, nonce []byte) []byte {
	h := hkdf.New(sha256.New, fileKey, nonce, []byte("payload"))
	streamKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, streamKey); err != nil {
		panic("age: internal error: failed to read from HKDF: " + err.Error())
	}
	return streamKey
}
