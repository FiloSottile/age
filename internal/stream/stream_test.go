// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stream_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"filippo.io/age/internal/stream"
	"golang.org/x/crypto/chacha20poly1305"
)

const cs = stream.ChunkSize

func TestRoundTrip(t *testing.T) {
	for _, stepSize := range []int{512, 600, 1000, cs} {
		for _, length := range []int{0, 1000, cs, cs + 100} {
			t.Run(fmt.Sprintf("len=%d,step=%d", length, stepSize),
				func(t *testing.T) { testRoundTrip(t, stepSize, length) })
		}
	}
}

func testRoundTrip(t *testing.T, stepSize, length int) {
	src := make([]byte, length)
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	w, err := stream.NewWriter(key, buf)
	if err != nil {
		t.Fatal(err)
	}

	var n int
	for n < length {
		b := length - n
		if b > stepSize {
			b = stepSize
		}
		nn, err := w.Write(src[n : n+b])
		if err != nil {
			t.Fatal(err)
		}
		if nn != b {
			t.Errorf("Write returned %d, expected %d", nn, b)
		}
		n += nn

		nn, err = w.Write(src[n:n])
		if err != nil {
			t.Fatal(err)
		}
		if nn != 0 {
			t.Errorf("Write returned %d, expected 0", nn)
		}
	}

	if err := w.Close(); err != nil {
		t.Error("Close returned an error:", err)
	}

	t.Logf("buffer size: %d", buf.Len())

	r, err := stream.NewReader(key, buf)
	if err != nil {
		t.Fatal(err)
	}

	n = 0
	readBuf := make([]byte, stepSize)
	for n < length {
		nn, err := r.Read(readBuf)
		if err != nil {
			t.Fatalf("Read error at index %d: %v", n, err)
		}

		if !bytes.Equal(readBuf[:nn], src[n:n+nn]) {
			t.Errorf("wrong data at indexes %d - %d", n, n+nn)
		}

		n += nn
	}
}
