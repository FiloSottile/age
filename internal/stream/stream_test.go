// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stream_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
	"testing/iotest"

	"filippo.io/age/internal/stream"
	"golang.org/x/crypto/chacha20poly1305"
)

const cs = stream.ChunkSize

// encrypt encrypts plaintext with key and returns the ciphertext.
func encrypt(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
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
	return buf.Bytes()
}

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
	rand.Read(src)
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
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
	rand.Read(key)

	// Create plaintext spanning exactly 3 chunks: 2 full chunks + partial third
	// Chunk 0: [0, cs)
	// Chunk 1: [cs, 2*cs)
	// Chunk 2: [2*cs, 2*cs+500)
	plaintextSize := 2*cs + 500
	plaintext := make([]byte, plaintextSize)
	rand.Read(plaintext)
	ciphertext := encrypt(t, key, plaintext)

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
			end := min(int(off)+n, plaintextSize)
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

// eofReaderAt wraps a bytes.Reader and forces it to return io.EOF alongside a
// read that successfully reaches the exact end of the data.
type eofReaderAt struct {
	r *bytes.Reader
}

func (e *eofReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := e.r.ReadAt(p, off)
	if err == nil && off+int64(n) == e.r.Size() {
		err = io.EOF
	}
	return n, err
}

func TestDecryptReaderAtEOF(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	// Multiple chunks, so that reads reach the final chunk both in the
	// constructor and through ReadAt.
	plaintext := make([]byte, 2*cs+100)
	rand.Read(plaintext)
	ciphertext := encrypt(t, key, plaintext)

	// An io.ReaderAt is allowed to return io.EOF alongside a successful read
	// that reaches the end of the source; both the constructor (which reads
	// the final chunk eagerly) and ReadAt must tolerate it.
	er := &eofReaderAt{r: bytes.NewReader(ciphertext)}

	ra, err := stream.NewDecryptReaderAt(key, er, int64(len(ciphertext)))
	if err != nil {
		t.Fatalf("NewDecryptReaderAt failed on EOF: %v", err)
	}

	// Sequential small reads evict the final chunk from the cache, so it is
	// read again through ReadAt, exercising its own EOF handling.
	got, err := io.ReadAll(io.NewSectionReader(ra, 0, int64(len(plaintext))))
	if err != nil {
		t.Fatalf("ReadAll failed on EOF: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("plaintext mismatch")
	}
}

// TestDecryptReaderTrailingData checks that data appended after a full-length
// final chunk is rejected, including when the source returns the trailing byte
// alongside io.EOF as permitted by io.Reader.
func TestDecryptReaderTrailingData(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	// A plaintext of exactly one full chunk, so the trailing data can only be
	// detected by reading past the final chunk.
	plaintext := make([]byte, cs)
	rand.Read(plaintext)
	ciphertext := encrypt(t, key, plaintext)
	trailing := append(bytes.Clone(ciphertext), 0x42)

	wrappers := map[string]func(io.Reader) io.Reader{
		"plain":   func(r io.Reader) io.Reader { return r },
		"dataErr": iotest.DataErrReader,
	}
	for name, wrap := range wrappers {
		t.Run(name, func(t *testing.T) {
			r, err := stream.NewDecryptReader(key, wrap(bytes.NewReader(trailing)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(r); err == nil {
				t.Error("trailing data: expected error, got nil")
			}

			r, err = stream.NewDecryptReader(key, wrap(bytes.NewReader(ciphertext)))
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Errorf("valid file: got err=%v, want nil", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Error("valid file: plaintext mismatch")
			}
		})
	}
}

func TestDecryptReaderAtEmpty(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	// Create empty encrypted file
	ciphertext := encrypt(t, key, nil)

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
	rand.Read(key)

	// Single chunk, not full
	plaintext := make([]byte, 1000)
	rand.Read(plaintext)
	ciphertext := encrypt(t, key, plaintext)

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
	rand.Read(key)

	// Exactly 2 full chunks
	plaintext := make([]byte, 2*cs)
	rand.Read(plaintext)
	ciphertext := encrypt(t, key, plaintext)

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
	rand.Read(key)
	plaintext := make([]byte, 1000)
	rand.Read(plaintext)
	ciphertext := encrypt(t, key, plaintext)

	// Try to decrypt with wrong key
	wrongKey := make([]byte, chacha20poly1305.KeySize)
	rand.Read(wrongKey)
	_, err := stream.NewDecryptReaderAt(wrongKey, bytes.NewReader(ciphertext), int64(len(ciphertext)))
	if err == nil {
		t.Error("wrong key: expected error, got nil")
	}
}

func TestDecryptReaderAtInvalidSize(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	plaintext := make([]byte, 1000)
	rand.Read(plaintext)
	ciphertext := encrypt(t, key, plaintext)

	// Wrong size (too small)
	_, err := stream.NewDecryptReaderAt(key, bytes.NewReader(ciphertext), int64(len(ciphertext)-1))
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

	// Negative sizes and sizes that would overflow the chunk count computation
	// must be rejected with an error rather than a panic.
	for _, size := range []int64{-1, -70000, math.MaxInt64, math.MaxInt64 - 200, math.MaxInt64 - 65550} {
		if _, err := stream.EncryptedChunkCount(size); err == nil {
			t.Errorf("EncryptedChunkCount(%d): expected error, got nil", size)
		}
		if _, err := stream.NewDecryptReaderAt(key, bytes.NewReader(ciphertext), size); err == nil {
			t.Errorf("NewDecryptReaderAt(%d): expected error, got nil", size)
		}
	}
}

func TestDecryptReaderAtTruncated(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	plaintext := make([]byte, 2*cs+500)
	rand.Read(plaintext)
	ciphertext := encrypt(t, key, plaintext)

	// Truncate ciphertext but lie about size. The source ending before the
	// expected end of the final chunk must be reported as an unexpected EOF,
	// not as a decryption failure.
	truncated := ciphertext[:len(ciphertext)-100]
	_, err := stream.NewDecryptReaderAt(key, bytes.NewReader(truncated), int64(len(ciphertext)))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated: got err=%v, want io.ErrUnexpectedEOF", err)
	}
}

func TestDecryptReaderAtTruncatedChunk(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	// Create 4 chunks: 3 full + 1 partial
	plaintext := make([]byte, 3*cs+500)
	rand.Read(plaintext)
	ciphertext := encrypt(t, key, plaintext)

	// Truncate to 3 chunks (remove the actual final chunk)
	// The third chunk was NOT encrypted with the last chunk flag,
	// so decryption should fail when we try to use it as the final chunk.
	encChunkSize := cs + 16 // ChunkSize + Overhead
	truncatedSize := int64(3 * encChunkSize)
	truncated := ciphertext[:truncatedSize]

	_, err := stream.NewDecryptReaderAt(key, bytes.NewReader(truncated), truncatedSize)
	if err == nil {
		t.Error("truncated at chunk boundary: expected error, got nil")
	}
}

func TestDecryptReaderAtConcurrent(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	// Create plaintext spanning 3 chunks: 2 full + partial
	plaintextSize := 2*cs + 500
	plaintext := make([]byte, plaintextSize)
	rand.Read(plaintext)
	ciphertext := encrypt(t, key, plaintext)

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
	rand.Read(key)
	plaintext := make([]byte, 2*cs+500)
	rand.Read(plaintext)
	ciphertext := encrypt(t, key, plaintext)

	// Corrupt final chunk - should fail in constructor
	corruptedFinal := bytes.Clone(ciphertext)
	corruptedFinal[len(corruptedFinal)-10] ^= 0xFF
	_, err := stream.NewDecryptReaderAt(key, bytes.NewReader(corruptedFinal), int64(len(corruptedFinal)))
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

func TestStreamAllocs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping allocation test in short mode")
	}
	const runs = 10

	// Setup the key and enough plaintext for the
	// AllocsPerRun warmup (1) + 10 runs + 1 to
	// ensure we stay in the full chunk hot path
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)
	plaintext := make([]byte, (runs+2)*cs)
	rand.Read(plaintext)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [chacha20poly1305.NonceSize]byte

	// The crypto implementation can allocate, so only check that the
	// age stream doesn't add any allocations of its own. So the test
	// is:
	//  1. Measure allocs using direct aead
	//  2. Measure allocs using stream.New[Encrypt|Decrypt]Writer

	t.Run("EncryptWriter", func(t *testing.T) {
		out := make([]byte, 0, cs+aead.Overhead())
		baselineAllocs := testing.AllocsPerRun(runs, func() {
			aead.Seal(out[:0], nonce[:], plaintext[:cs], nil)
		})

		w, err := stream.NewEncryptWriter(key, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		chunks := plaintext
		streamAllocs := testing.AllocsPerRun(runs, func() {
			if _, err := w.Write(chunks[:cs]); err != nil {
				t.Fatal(err)
			}
			chunks = chunks[cs:]
		})
		if streamAllocs > baselineAllocs {
			t.Errorf("EncryptWriter allocated %v times per chunk; the crypto implementation allocated %v", streamAllocs, baselineAllocs)
		}
	})

	t.Run("DecryptReader", func(t *testing.T) {
		ciphertext := aead.Seal(nil, nonce[:], plaintext[:cs], nil)
		out := make([]byte, 0, cs)
		baselineAllocs := testing.AllocsPerRun(runs, func() {
			if _, err := aead.Open(out[:0], nonce[:], ciphertext, nil); err != nil {
				t.Fatal(err)
			}
		})

		r, err := stream.NewDecryptReader(key, bytes.NewReader(encrypt(t, key, plaintext)))
		if err != nil {
			t.Fatal(err)
		}
		p := make([]byte, cs)
		streamAllocs := testing.AllocsPerRun(runs, func() {
			if _, err := io.ReadFull(r, p); err != nil {
				t.Fatal(err)
			}
		})
		if streamAllocs > baselineAllocs {
			t.Errorf("DecryptReader allocated %v times per chunk; the crypto implementation allocated %v", streamAllocs, baselineAllocs)
		}
	})
}

func BenchmarkEncryptWriter(b *testing.B) {
	for _, size := range []int{cs, 1 << 20, 16 << 20} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			key := make([]byte, chacha20poly1305.KeySize)
			rand.Read(key)
			plaintext := make([]byte, size)
			rand.Read(plaintext)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				w, err := stream.NewEncryptWriter(key, io.Discard)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := w.Write(plaintext); err != nil {
					b.Fatal(err)
				}
				if err := w.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecryptReader(b *testing.B) {
	for _, size := range []int{cs, 1 << 20, 16 << 20} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			key := make([]byte, chacha20poly1305.KeySize)
			rand.Read(key)
			plaintext := make([]byte, size)
			rand.Read(plaintext)
			buf := &bytes.Buffer{}
			w, err := stream.NewEncryptWriter(key, buf)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := w.Write(plaintext); err != nil {
				b.Fatal(err)
			}
			if err := w.Close(); err != nil {
				b.Fatal(err)
			}
			ciphertext := buf.Bytes()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				r, err := stream.NewDecryptReader(key, bytes.NewReader(ciphertext))
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, r); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
