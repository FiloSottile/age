// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stream_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"testing/iotest"

	"filippo.io/age/internal/stream"
	"golang.org/x/crypto/chacha20poly1305"
)

const cs = stream.ChunkSize

func TestRoundTrip(t *testing.T) {
	for _, length := range []int{0, 1000, cs - 1, cs, cs + 1, cs + 100, 2 * cs, 2*cs + 500} {
		for _, stepSize := range []int{512, 600, 1000, cs - 1, cs, cs + 1} {
			t.Run(fmt.Sprintf("len=%d,step=%d", length, stepSize), func(t *testing.T) {
				testRoundTrip(t, stepSize, length)
			})
		}
	}

	length, stepSize := 2*cs+500, 1
	t.Run(fmt.Sprintf("len=%d,step=%d", length, stepSize), func(t *testing.T) {
		testRoundTrip(t, stepSize, length)
	})
}

func testRoundTrip(t *testing.T, stepSize, length int) {
	src := make([]byte, length)
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte

	t.Run("EncryptWriter", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w, err := stream.NewEncryptWriter(key, buf)
		if err != nil {
			t.Fatal(err)
		}

		var n int
		for n < length {
			b := min(length-n, stepSize)
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

		ciphertext = buf.Bytes()
	})

	t.Run("DecryptReader", func(t *testing.T) {
		r, err := stream.NewDecryptReader(key, bytes.NewReader(ciphertext))
		if err != nil {
			t.Fatal(err)
		}

		var n int
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

		t.Run("TestReader", func(t *testing.T) {
			if length > 1000 && testing.Short() {
				t.Skip("skipping slow iotest.TestReader on long input")
			}
			r, _ := stream.NewDecryptReader(key, bytes.NewReader(ciphertext))
			if err := iotest.TestReader(r, src); err != nil {
				t.Error("iotest.TestReader error on DecryptReader:", err)
			}
		})
	})

	t.Run("DecryptReaderAt", func(t *testing.T) {
		rAt, err := stream.NewDecryptReaderAt(key, bytes.NewReader(ciphertext), int64(len(ciphertext)))
		if err != nil {
			t.Fatal(err)
		}
		rr := io.NewSectionReader(rAt, 0, int64(len(ciphertext)))

		var n int
		readBuf := make([]byte, stepSize)
		for n < length {
			nn, err := rr.Read(readBuf)
			if n+nn == length && err == io.EOF {
				err = nil
			}
			if err != nil {
				t.Fatalf("ReadAt error at index %d: %v", n, err)
			}

			if !bytes.Equal(readBuf[:nn], src[n:n+nn]) {
				t.Errorf("wrong data at indexes %d - %d", n, n+nn)
			}

			n += nn
		}

		t.Run("TestReader", func(t *testing.T) {
			if length > 1000 && testing.Short() {
				t.Skip("skipping slow iotest.TestReader on long input")
			}
			rr := io.NewSectionReader(rAt, 0, int64(len(src)))
			if err := iotest.TestReader(rr, src); err != nil {
				t.Error("iotest.TestReader error on DecryptReaderAt:", err)
			}
		})
	})

	t.Run("EncryptReader", func(t *testing.T) {
		er, err := stream.NewEncryptReader(key, bytes.NewReader(src))
		if err != nil {
			t.Fatal(err)
		}

		var n int
		readBuf := make([]byte, stepSize)
		for {
			nn, err := er.Read(readBuf)
			if nn == 0 && err == io.EOF {
				break
			} else if err != nil {
				t.Fatalf("EncryptReader Read error at index %d: %v", n, err)
			}

			if !bytes.Equal(readBuf[:nn], ciphertext[n:n+nn]) {
				t.Errorf("EncryptReader wrong data at indexes %d - %d", n, n+nn)
			}

			n += nn
		}
		if n != len(ciphertext) {
			t.Errorf("EncryptReader read %d bytes, expected %d", n, len(ciphertext))
		}

		t.Run("TestReader", func(t *testing.T) {
			if length > 1000 && testing.Short() {
				t.Skip("skipping slow iotest.TestReader on long input")
			}
			er, _ := stream.NewEncryptReader(key, bytes.NewReader(src))
			if err := iotest.TestReader(er, ciphertext); err != nil {
				t.Error("iotest.TestReader error on EncryptReader:", err)
			}
		})
	})
}

// trackingReaderAt wraps an io.ReaderAt and tracks whether ReadAt was called.
type trackingReaderAt struct {
	r      io.ReaderAt
	called bool
}

func (t *trackingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	t.called = true
	return t.r.ReadAt(p, off)
}

func (t *trackingReaderAt) reset() {
	t.called = false
}

func TestDecryptReaderAt(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// Create plaintext spanning exactly 3 chunks: 2 full chunks + partial third
	// Chunk 0: [0, cs)
	// Chunk 1: [cs, 2*cs)
	// Chunk 2: [2*cs, 2*cs+500)
	plaintextSize := 2*cs + 500
	plaintext := make([]byte, plaintextSize)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	// Encrypt
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
	ciphertext := buf.Bytes()

	// Create tracking ReaderAt
	tracker := &trackingReaderAt{r: bytes.NewReader(ciphertext)}

	// Create DecryptReaderAt (this reads and caches the final chunk)
	ra, err := stream.NewDecryptReaderAt(key, tracker, int64(len(ciphertext)))
	if err != nil {
		t.Fatal(err)
	}
	tracker.reset()

	// Helper to check reads
	checkRead := func(name string, off int64, size int, wantN int, wantEOF bool, wantSrcRead bool) {
		t.Helper()
		tracker.reset()
		p := make([]byte, size)
		n, err := ra.ReadAt(p, off)

		if wantEOF {
			if err != io.EOF {
				t.Errorf("%s: got err=%v, want EOF", name, err)
			}
		} else {
			if err != nil {
				t.Errorf("%s: got err=%v, want nil", name, err)
			}
		}

		if n != wantN {
			t.Errorf("%s: got n=%d, want %d", name, n, wantN)
		}

		if tracker.called != wantSrcRead {
			t.Errorf("%s: src.ReadAt called=%v, want %v", name, tracker.called, wantSrcRead)
		}

		// Verify data correctness
		if n > 0 && off >= 0 && off < int64(plaintextSize) {
			end := int(off) + n
			if end > plaintextSize {
				end = plaintextSize
			}
			if !bytes.Equal(p[:n], plaintext[off:end]) {
				t.Errorf("%s: data mismatch", name)
			}
		}
	}

	// Test 1: Read from final chunk (cached by constructor)
	checkRead("final chunk (cached)", int64(2*cs+100), 100, 100, false, false)

	// Test 2: Read spanning second and third chunk
	checkRead("span chunks 1-2", int64(cs+cs-50), 100, 100, false, true)

	// Test 3: Read from final chunk again (cached from test 2)
	// When reading across chunks 1-2 in test 2, the loop processes chunk 1 then chunk 2,
	// so chunk 2 ends up in the cache.
	checkRead("final chunk after span", int64(2*cs+200), 100, 100, false, false)

	// Test 4: Read from final chunk again (now cached)
	checkRead("final chunk (cached again)", int64(2*cs+50), 50, 50, false, false)

	// Test 5: Read from first chunk (not cached)
	checkRead("first chunk", 0, 100, 100, false, true)

	// Test 6: Read from first chunk again (now cached)
	checkRead("first chunk (cached)", 50, 100, 100, false, false)

	// Test 7: Read spanning all chunks
	tracker.reset()
	p := make([]byte, plaintextSize)
	n, err := ra.ReadAt(p, 0)
	if err != io.EOF {
		t.Errorf("span all: got err=%v, want EOF", err)
	}
	if n != plaintextSize {
		t.Errorf("span all: got n=%d, want %d", n, plaintextSize)
	}
	if !bytes.Equal(p, plaintext) {
		t.Errorf("span all: data mismatch")
	}

	// Test 8: Read beyond the end (offset > size)
	tracker.reset()
	p = make([]byte, 100)
	n, err = ra.ReadAt(p, int64(plaintextSize+100))
	if err == nil {
		t.Error("beyond end: expected error, got nil")
	}
	if n != 0 {
		t.Errorf("beyond end: got n=%d, want 0", n)
	}

	// Test 9: Read with off = size (should return 0, EOF)
	tracker.reset()
	p = make([]byte, 100)
	n, err = ra.ReadAt(p, int64(plaintextSize))
	if err != io.EOF {
		t.Errorf("off=size: got err=%v, want EOF", err)
	}
	if n != 0 {
		t.Errorf("off=size: got n=%d, want 0", n)
	}

	// Test 10: Read spanning last chunk and beyond
	tracker.reset()
	p = make([]byte, 1000) // request more than available
	n, err = ra.ReadAt(p, int64(2*cs+400))
	if err != io.EOF {
		t.Errorf("span last+beyond: got err=%v, want EOF", err)
	}
	wantN := 500 - 400 // only 100 bytes available from offset 2*cs+400
	if n != wantN {
		t.Errorf("span last+beyond: got n=%d, want %d", n, wantN)
	}
	if !bytes.Equal(p[:n], plaintext[2*cs+400:]) {
		t.Error("span last+beyond: data mismatch")
	}

	// Test 11: Read spanning second+last chunk and beyond
	tracker.reset()
	p = make([]byte, cs+1000) // request more than available
	n, err = ra.ReadAt(p, int64(cs+100))
	if err != io.EOF {
		t.Errorf("span 1-2+beyond: got err=%v, want EOF", err)
	}
	wantN = plaintextSize - (cs + 100)
	if n != wantN {
		t.Errorf("span 1-2+beyond: got n=%d, want %d", n, wantN)
	}
	if !bytes.Equal(p[:n], plaintext[cs+100:]) {
		t.Error("span 1-2+beyond: data mismatch")
	}

	// Test 12: Negative offset
	tracker.reset()
	p = make([]byte, 100)
	n, err = ra.ReadAt(p, -1)
	if err == nil {
		t.Error("negative offset: expected error, got nil")
	}
	if n != 0 {
		t.Errorf("negative offset: got n=%d, want 0", n)
	}

	// Test 13: Zero-length read in the middle
	tracker.reset()
	p = make([]byte, 0)
	n, err = ra.ReadAt(p, 100)
	if err != nil {
		t.Errorf("zero-length middle: got err=%v, want nil", err)
	}
	if n != 0 {
		t.Errorf("zero-length middle: got n=%d, want 0", n)
	}

	// Test 14: Zero-length read at end
	tracker.reset()
	p = make([]byte, 0)
	n, err = ra.ReadAt(p, int64(plaintextSize))
	if err != nil {
		t.Errorf("zero-length end: got err=%v, want nil", err)
	}
	if n != 0 {
		t.Errorf("zero-length end: got n=%d, want 0", n)
	}

	// Test 15: Read exactly one chunk at chunk boundary
	checkRead("exact chunk at boundary", int64(cs), cs, cs, false, true)

	// Test 16: Read one byte at each chunk boundary
	checkRead("one byte at start", 0, 1, 1, false, true)
	checkRead("one byte at cs-1", int64(cs-1), 1, 1, false, false) // cached from test 15
	checkRead("one byte at cs", int64(cs), 1, 1, false, true)
	checkRead("one byte at 2*cs-1", int64(2*cs-1), 1, 1, false, false) // same chunk
	checkRead("one byte at 2*cs", int64(2*cs), 1, 1, false, true)
	checkRead("last byte", int64(plaintextSize-1), 1, 1, true, false) // same chunk, EOF because we reach end

	// Test 17: Read crossing exactly one chunk boundary
	checkRead("cross boundary 0-1", int64(cs-50), 100, 100, false, true)
	checkRead("cross boundary 1-2", int64(2*cs-50), 100, 100, false, true)
}

func TestDecryptReaderAtEmpty(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// Create empty encrypted file
	buf := &bytes.Buffer{}
	w, err := stream.NewEncryptWriter(key, buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	ciphertext := buf.Bytes()

	tracker := &trackingReaderAt{r: bytes.NewReader(ciphertext)}
	ra, err := stream.NewDecryptReaderAt(key, tracker, int64(len(ciphertext)))
	if err != nil {
		t.Fatal(err)
	}
	tracker.reset()

	// Test 1: Read from empty file at offset 0
	p := make([]byte, 100)
	n, err := ra.ReadAt(p, 0)
	if err != io.EOF {
		t.Errorf("empty read: got err=%v, want EOF", err)
	}
	if n != 0 {
		t.Errorf("empty read: got n=%d, want 0", n)
	}

	// Test 2: Zero-length read from empty file
	p = make([]byte, 0)
	n, err = ra.ReadAt(p, 0)
	if err != nil {
		t.Errorf("empty zero-length: got err=%v, want nil", err)
	}
	if n != 0 {
		t.Errorf("empty zero-length: got n=%d, want 0", n)
	}

	// Test 3: Read beyond empty file
	p = make([]byte, 100)
	n, err = ra.ReadAt(p, 1)
	if err == nil {
		t.Error("empty beyond: expected error, got nil")
	}
	if n != 0 {
		t.Errorf("empty beyond: got n=%d, want 0", n)
	}
}

func TestDecryptReaderAtSingleChunk(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// Single chunk, not full
	plaintext := make([]byte, 1000)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
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
	ciphertext := buf.Bytes()

	tracker := &trackingReaderAt{r: bytes.NewReader(ciphertext)}
	ra, err := stream.NewDecryptReaderAt(key, tracker, int64(len(ciphertext)))
	if err != nil {
		t.Fatal(err)
	}
	tracker.reset()

	// All reads should use cache (final chunk = only chunk)
	p := make([]byte, 100)
	n, err := ra.ReadAt(p, 0)
	if err != nil {
		t.Errorf("single chunk start: got err=%v, want nil", err)
	}
	if n != 100 {
		t.Errorf("single chunk start: got n=%d, want 100", n)
	}
	if tracker.called {
		t.Error("single chunk start: unexpected src.ReadAt call")
	}
	if !bytes.Equal(p[:n], plaintext[:100]) {
		t.Error("single chunk start: data mismatch")
	}

	// Read at end
	n, err = ra.ReadAt(p, 900)
	if err != io.EOF {
		t.Errorf("single chunk end: got err=%v, want EOF", err)
	}
	if n != 100 {
		t.Errorf("single chunk end: got n=%d, want 100", n)
	}
	if tracker.called {
		t.Error("single chunk end: unexpected src.ReadAt call")
	}
	if !bytes.Equal(p[:n], plaintext[900:]) {
		t.Error("single chunk end: data mismatch")
	}
}

func TestDecryptReaderAtFullChunks(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// Exactly 2 full chunks
	plaintext := make([]byte, 2*cs)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
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
	ciphertext := buf.Bytes()

	tracker := &trackingReaderAt{r: bytes.NewReader(ciphertext)}
	ra, err := stream.NewDecryptReaderAt(key, tracker, int64(len(ciphertext)))
	if err != nil {
		t.Fatal(err)
	}
	tracker.reset()

	// Read last byte of second chunk (cached)
	p := make([]byte, 1)
	n, err := ra.ReadAt(p, int64(2*cs-1))
	if err != io.EOF {
		t.Errorf("last byte: got err=%v, want EOF", err)
	}
	if n != 1 {
		t.Errorf("last byte: got n=%d, want 1", n)
	}
	if tracker.called {
		t.Error("last byte: unexpected src.ReadAt call (should be cached)")
	}
	if p[0] != plaintext[2*cs-1] {
		t.Error("last byte: data mismatch")
	}

	// Read at exactly the boundary between chunks
	p = make([]byte, 100)
	n, err = ra.ReadAt(p, int64(cs-50))
	if err != nil {
		t.Errorf("boundary: got err=%v, want nil", err)
	}
	if n != 100 {
		t.Errorf("boundary: got n=%d, want 100", n)
	}
	if !bytes.Equal(p, plaintext[cs-50:cs+50]) {
		t.Error("boundary: data mismatch")
	}
}

func TestDecryptReaderAtWrongKey(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 1000)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
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
	ciphertext := buf.Bytes()

	// Try to decrypt with wrong key
	wrongKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatal(err)
	}

	_, err = stream.NewDecryptReaderAt(wrongKey, bytes.NewReader(ciphertext), int64(len(ciphertext)))
	if err == nil {
		t.Error("wrong key: expected error, got nil")
	}
}

func TestDecryptReaderAtInvalidSize(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 1000)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
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
	ciphertext := buf.Bytes()

	// Wrong size (too small)
	_, err = stream.NewDecryptReaderAt(key, bytes.NewReader(ciphertext), int64(len(ciphertext)-1))
	if err == nil {
		t.Error("wrong size (small): expected error, got nil")
	}

	// Wrong size (too large)
	_, err = stream.NewDecryptReaderAt(key, bytes.NewReader(ciphertext), int64(len(ciphertext)+1))
	if err == nil {
		t.Error("wrong size (large): expected error, got nil")
	}

	// Size that would imply empty final chunk (invalid)
	// This would be: one full encrypted chunk + just overhead
	invalidSize := int64(cs + chacha20poly1305.Overhead + chacha20poly1305.Overhead)
	_, err = stream.NewDecryptReaderAt(key, bytes.NewReader(make([]byte, invalidSize)), invalidSize)
	if err == nil {
		t.Error("invalid size (empty final chunk): expected error, got nil")
	}
}

func TestDecryptReaderAtTruncated(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 2*cs+500)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
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
	ciphertext := buf.Bytes()

	// Truncate ciphertext but lie about size
	truncated := ciphertext[:len(ciphertext)-100]
	_, err = stream.NewDecryptReaderAt(key, bytes.NewReader(truncated), int64(len(ciphertext)))
	if err == nil {
		t.Error("truncated: expected error, got nil")
	}
}

func TestDecryptReaderAtTruncatedChunk(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// Create 4 chunks: 3 full + 1 partial
	plaintext := make([]byte, 3*cs+500)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
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
	ciphertext := buf.Bytes()

	// Truncate to 3 chunks (remove the actual final chunk)
	// The third chunk was NOT encrypted with the last chunk flag,
	// so decryption should fail when we try to use it as the final chunk.
	encChunkSize := cs + 16 // ChunkSize + Overhead
	truncatedSize := int64(3 * encChunkSize)
	truncated := ciphertext[:truncatedSize]

	_, err = stream.NewDecryptReaderAt(key, bytes.NewReader(truncated), truncatedSize)
	if err == nil {
		t.Error("truncated at chunk boundary: expected error, got nil")
	}
}

func TestDecryptReaderAtConcurrent(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// Create plaintext spanning 3 chunks: 2 full + partial
	plaintextSize := 2*cs + 500
	plaintext := make([]byte, plaintextSize)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	// Encrypt
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
	ciphertext := buf.Bytes()

	ra, err := stream.NewDecryptReaderAt(key, bytes.NewReader(ciphertext), int64(len(ciphertext)))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("same chunk", func(t *testing.T) {
		t.Parallel()
		const goroutines = 10
		const iterations = 100
		errc := make(chan error, goroutines)

		for g := range goroutines {
			go func(id int) {
				for i := range iterations {
					off := int64((id*iterations + i) % 500)
					p := make([]byte, 100)
					n, err := ra.ReadAt(p, off)
					if err != nil {
						errc <- fmt.Errorf("goroutine %d iter %d: %v", id, i, err)
						return
					}
					if n != 100 {
						errc <- fmt.Errorf("goroutine %d iter %d: n=%d, want 100", id, i, n)
						return
					}
					if !bytes.Equal(p, plaintext[off:off+100]) {
						errc <- fmt.Errorf("goroutine %d iter %d: data mismatch", id, i)
						return
					}
				}
				errc <- nil
			}(g)
		}

		for range goroutines {
			if err := <-errc; err != nil {
				t.Error(err)
			}
		}
	})

	t.Run("different chunks", func(t *testing.T) {
		t.Parallel()
		const goroutines = 10
		const iterations = 100
		errc := make(chan error, goroutines)

		for g := range goroutines {
			go func(id int) {
				for i := range iterations {
					// Each goroutine reads from a different chunk based on id
					chunkIdx := id % 3
					off := int64(chunkIdx*cs + (i % 400))
					size := 100
					if off+int64(size) > int64(plaintextSize) {
						size = plaintextSize - int(off)
					}
					p := make([]byte, size)
					n, err := ra.ReadAt(p, off)
					if n == size && err == io.EOF {
						err = nil // EOF at end is acceptable
					}
					if err != nil {
						errc <- fmt.Errorf("goroutine %d iter %d: off=%d: %v", id, i, off, err)
						return
					}
					if n != size {
						errc <- fmt.Errorf("goroutine %d iter %d: n=%d, want %d", id, i, n, size)
						return
					}
					if !bytes.Equal(p[:n], plaintext[off:off+int64(n)]) {
						errc <- fmt.Errorf("goroutine %d iter %d: data mismatch", id, i)
						return
					}
				}
				errc <- nil
			}(g)
		}

		for range goroutines {
			if err := <-errc; err != nil {
				t.Error(err)
			}
		}
	})

	t.Run("across chunks", func(t *testing.T) {
		t.Parallel()
		const goroutines = 10
		const iterations = 100
		errc := make(chan error, goroutines)

		for g := range goroutines {
			go func(id int) {
				for i := range iterations {
					// Read across chunk boundaries
					boundary := (id%2 + 1) * cs // either cs or 2*cs
					off := int64(boundary - 50 + (i % 30))
					size := 100
					if off+int64(size) > int64(plaintextSize) {
						size = plaintextSize - int(off)
					}
					if size <= 0 {
						continue
					}
					p := make([]byte, size)
					n, err := ra.ReadAt(p, off)
					if n == size && err == io.EOF {
						err = nil
					}
					if err != nil {
						errc <- fmt.Errorf("goroutine %d iter %d: off=%d size=%d: %v", id, i, off, size, err)
						return
					}
					if n != size {
						errc <- fmt.Errorf("goroutine %d iter %d: n=%d, want %d", id, i, n, size)
						return
					}
					if !bytes.Equal(p[:n], plaintext[off:off+int64(n)]) {
						errc <- fmt.Errorf("goroutine %d iter %d: data mismatch", id, i)
						return
					}
				}
				errc <- nil
			}(g)
		}

		for range goroutines {
			if err := <-errc; err != nil {
				t.Error(err)
			}
		}
	})
}

func TestDecryptReaderAtCorrupted(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 2*cs+500)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
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
	ciphertext := bytes.Clone(buf.Bytes())

	// Corrupt final chunk - should fail in constructor
	corruptedFinal := bytes.Clone(ciphertext)
	corruptedFinal[len(corruptedFinal)-10] ^= 0xFF
	_, err = stream.NewDecryptReaderAt(key, bytes.NewReader(corruptedFinal), int64(len(corruptedFinal)))
	if err == nil {
		t.Error("corrupted final: expected error, got nil")
	}

	// Corrupt first chunk - should fail on read
	corruptedFirst := bytes.Clone(ciphertext)
	corruptedFirst[10] ^= 0xFF
	ra, err := stream.NewDecryptReaderAt(key, bytes.NewReader(corruptedFirst), int64(len(corruptedFirst)))
	if err != nil {
		t.Fatalf("corrupted first constructor: unexpected error: %v", err)
	}
	p := make([]byte, 100)
	_, err = ra.ReadAt(p, 0)
	if err == nil {
		t.Error("corrupted first read: expected error, got nil")
	}
}
