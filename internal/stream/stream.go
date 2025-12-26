// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stream implements a variant of the STREAM chunked encryption scheme.
package stream

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const ChunkSize = 64 * 1024

func EncryptedChunkCount(encryptedSize int64) (int64, error) {
	chunks := (encryptedSize + encChunkSize - 1) / encChunkSize

	plaintextSize := encryptedSize - chunks*chacha20poly1305.Overhead
	expChunks := (plaintextSize + ChunkSize - 1) / ChunkSize
	// Empty plaintext, the only case that allows (and requires) an empty chunk.
	if plaintextSize == 0 {
		expChunks = 1
	}
	if expChunks != chunks {
		return 0, fmt.Errorf("invalid encrypted payload size: %d", encryptedSize)
	}

	return chunks, nil
}

func PlaintextSize(encryptedSize int64) (int64, error) {
	chunks, err := EncryptedChunkCount(encryptedSize)
	if err != nil {
		return 0, err
	}
	plaintextSize := encryptedSize - chunks*chacha20poly1305.Overhead
	return plaintextSize, nil
}

type DecryptReader struct {
	a   cipher.AEAD
	src io.Reader

	unread []byte // decrypted but unread data, backed by buf
	buf    [encChunkSize]byte

	err   error
	nonce [chacha20poly1305.NonceSize]byte
}

const (
	encChunkSize  = ChunkSize + chacha20poly1305.Overhead
	lastChunkFlag = 0x01
)

func NewDecryptReader(key []byte, src io.Reader) (*DecryptReader, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &DecryptReader{a: aead, src: src}, nil
}

func (r *DecryptReader) Read(p []byte) (int, error) {
	if len(r.unread) > 0 {
		n := copy(p, r.unread)
		r.unread = r.unread[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	last, err := r.readChunk()
	if err != nil {
		r.err = err
		return 0, err
	}

	n := copy(p, r.unread)
	r.unread = r.unread[n:]

	if last {
		// Ensure there is an EOF after the last chunk as expected. In other
		// words, check for trailing data after a full-length final chunk.
		// Hopefully, the underlying reader supports returning EOF even if it
		// had previously returned an EOF to ReadFull.
		if _, err := r.src.Read(make([]byte, 1)); err == nil {
			r.err = errors.New("trailing data after end of encrypted file")
		} else if err != io.EOF {
			r.err = fmt.Errorf("non-EOF error reading after end of encrypted file: %w", err)
		} else {
			r.err = io.EOF
		}
	}

	return n, nil
}

// readChunk reads the next chunk of ciphertext from r.src and makes it available
// in r.unread. last is true if the chunk was marked as the end of the message.
// readChunk must not be called again after returning a last chunk or an error.
func (r *DecryptReader) readChunk() (last bool, err error) {
	if len(r.unread) != 0 {
		panic("stream: internal error: readChunk called with dirty buffer")
	}

	in := r.buf[:]
	n, err := io.ReadFull(r.src, in)
	switch {
	case err == io.EOF:
		// A message can't end without a marked chunk. This message is truncated.
		return false, io.ErrUnexpectedEOF
	case err == io.ErrUnexpectedEOF:
		// The last chunk can be short, but not empty unless it's the first and
		// only chunk.
		if !nonceIsZero(&r.nonce) && n == r.a.Overhead() {
			return false, errors.New("last chunk is empty, try age v1.0.0, and please consider reporting this")
		}
		in = in[:n]
		last = true
		setLastChunkFlag(&r.nonce)
	case err != nil:
		return false, err
	}

	outBuf := make([]byte, 0, ChunkSize)
	out, err := r.a.Open(outBuf, r.nonce[:], in, nil)
	if err != nil && !last {
		// Check if this was a full-length final chunk.
		last = true
		setLastChunkFlag(&r.nonce)
		out, err = r.a.Open(outBuf, r.nonce[:], in, nil)
	}
	if err != nil {
		return false, errors.New("failed to decrypt and authenticate payload chunk, file may be corrupted or tampered with")
	}

	incNonce(&r.nonce)
	r.unread = r.buf[:copy(r.buf[:], out)]
	return last, nil
}

func incNonce(nonce *[chacha20poly1305.NonceSize]byte) {
	for i := len(nonce) - 2; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
	// The counter is 88 bits, this is unreachable.
	panic("stream: chunk counter wrapped around")
}

func nonceForChunk(chunkIndex int64) *[chacha20poly1305.NonceSize]byte {
	var nonce [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[3:11], uint64(chunkIndex))
	return &nonce
}

func setLastChunkFlag(nonce *[chacha20poly1305.NonceSize]byte) {
	nonce[len(nonce)-1] = lastChunkFlag
}

func nonceIsZero(nonce *[chacha20poly1305.NonceSize]byte) bool {
	return *nonce == [chacha20poly1305.NonceSize]byte{}
}

type EncryptWriter struct {
	a     cipher.AEAD
	dst   io.Writer
	buf   bytes.Buffer
	nonce [chacha20poly1305.NonceSize]byte
	err   error
}

func NewEncryptWriter(key []byte, dst io.Writer) (*EncryptWriter, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &EncryptWriter{a: aead, dst: dst}, nil
}

func (w *EncryptWriter) Write(p []byte) (n int, err error) {
	if w.err != nil {
		return 0, w.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	total := len(p)
	for len(p) > 0 {
		n := min(len(p), ChunkSize-w.buf.Len())
		w.buf.Write(p[:n])
		p = p[n:]

		// Only flush if there's a full chunk with bytes still to write, or we
		// can't know if this is the last chunk yet.
		if w.buf.Len() == ChunkSize && len(p) > 0 {
			if err := w.flushChunk(notLastChunk); err != nil {
				w.err = err
				return 0, err
			}
		}
	}
	return total, nil
}

// Close flushes the last chunk. It does not close the underlying Writer.
func (w *EncryptWriter) Close() error {
	if w.err != nil {
		return w.err
	}

	w.err = w.flushChunk(lastChunk)
	if w.err != nil {
		return w.err
	}

	w.err = errors.New("stream.Writer is already closed")
	return nil
}

const (
	lastChunk    = true
	notLastChunk = false
)

func (w *EncryptWriter) flushChunk(last bool) error {
	if !last && w.buf.Len() != ChunkSize {
		panic("stream: internal error: flush called with partial chunk")
	}

	if last {
		setLastChunkFlag(&w.nonce)
	}
	w.buf.Grow(chacha20poly1305.Overhead)
	ciphertext := w.a.Seal(w.buf.Bytes()[:0], w.nonce[:], w.buf.Bytes(), nil)
	_, err := w.dst.Write(ciphertext)
	incNonce(&w.nonce)
	w.buf.Reset()
	return err
}

type EncryptReader struct {
	a   cipher.AEAD
	src io.Reader

	// The first ready bytes of buf are already encrypted. This may be less than
	// buf.Len(), because we need to over-read to know if a chunk is the last.
	ready int
	buf   bytes.Buffer

	nonce [chacha20poly1305.NonceSize]byte
	err   error
}

func NewEncryptReader(key []byte, src io.Reader) (*EncryptReader, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &EncryptReader{a: aead, src: src}, nil
}

func (r *EncryptReader) Read(p []byte) (int, error) {
	if r.ready > 0 {
		n, err := r.buf.Read(p[:min(len(p), r.ready)])
		r.ready -= n
		return n, err
	}
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	if err := r.feedBuffer(); err != nil {
		r.err = err
		return 0, err
	}

	n, err := r.buf.Read(p[:min(len(p), r.ready)])
	r.ready -= n
	return n, err
}

// feedBuffer reads and encrypts the next chunk from r.src and appends it to
// r.buf. It sets r.ready to the number of newly available bytes in r.buf.
func (r *EncryptReader) feedBuffer() error {
	if r.ready > 0 {
		panic("stream: internal error: feedBuffer called with dirty buffer")
	}

	// CopyN will use r.buf.ReadFrom/WriteTo to fill the buffer directly.
	// We need ChunkSize + 1 bytes to determine if this is the last chunk.
	_, err := io.CopyN(&r.buf, r.src, int64(ChunkSize-r.buf.Len()+1))
	if err != nil && err != io.EOF {
		return err
	}

	if last := r.buf.Len() <= ChunkSize; last {
		setLastChunkFlag(&r.nonce)

		// After Grow, we know r.buf.Bytes() has enough capacity for the
		// overhead. We encrypt in place and then do a Write to include the
		// overhead in the buffer.
		r.buf.Grow(chacha20poly1305.Overhead)
		plaintext := r.buf.Bytes()
		r.a.Seal(plaintext[:0], r.nonce[:], plaintext, nil)
		incNonce(&r.nonce)
		r.buf.Write(plaintext[len(plaintext) : len(plaintext)+chacha20poly1305.Overhead])
		r.ready = r.buf.Len()

		r.err = io.EOF
		return nil
	}

	// Same, but accounting for the tail byte which will remain unencrypted and
	// needs to be shifted past the overhead.
	if r.buf.Len() != ChunkSize+1 {
		panic("stream: internal error: unexpected buffer length")
	}
	tailByte := r.buf.Bytes()[ChunkSize]
	r.buf.Grow(chacha20poly1305.Overhead)
	plaintext := r.buf.Bytes()[:ChunkSize]
	r.a.Seal(plaintext[:0], r.nonce[:], plaintext, nil)
	incNonce(&r.nonce)
	r.buf.Write(plaintext[len(plaintext)+1 : len(plaintext)+chacha20poly1305.Overhead])
	r.buf.WriteByte(tailByte)
	r.ready = ChunkSize + chacha20poly1305.Overhead

	return nil
}

type DecryptReaderAt struct {
	a      cipher.AEAD
	src    io.ReaderAt
	size   int64
	chunks int64
	cache  atomic.Pointer[cachedChunk]
}

type cachedChunk struct {
	off  int64
	data []byte
}

func NewDecryptReaderAt(key []byte, src io.ReaderAt, size int64) (*DecryptReaderAt, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Check that size is valid by decrypting the final chunk.
	chunks, err := EncryptedChunkCount(size)
	if err != nil {
		return nil, err
	}
	finalChunkIndex := chunks - 1
	finalChunkOff := finalChunkIndex * encChunkSize
	finalChunkSize := size - finalChunkOff
	finalChunk := make([]byte, finalChunkSize)
	if _, err := src.ReadAt(finalChunk, finalChunkOff); err != nil {
		return nil, fmt.Errorf("failed to read final chunk: %w", err)
	}
	nonce := nonceForChunk(finalChunkIndex)
	setLastChunkFlag(nonce)
	plaintext, err := aead.Open(finalChunk[:0], nonce[:], finalChunk, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt and authenticate final chunk: %w", err)
	}
	cache := &cachedChunk{off: finalChunkOff, data: plaintext}

	plaintextSize := size - chunks*chacha20poly1305.Overhead
	r := &DecryptReaderAt{a: aead, src: src, size: plaintextSize, chunks: chunks}
	r.cache.Store(cache)
	return r, nil
}

func (r *DecryptReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off > r.size {
		return 0, fmt.Errorf("offset out of range [0:%d]: %d", r.size, off)
	}
	if len(p) == 0 {
		return 0, nil
	}
	var cacheUpdate *cachedChunk
	chunk := make([]byte, encChunkSize)
	for len(p) > 0 && off < r.size {
		chunkIndex := off / ChunkSize
		chunkOff := chunkIndex * encChunkSize
		encSize := r.size + r.chunks*chacha20poly1305.Overhead
		chunkSize := min(encSize-chunkOff, encChunkSize)

		cached := r.cache.Load()
		var plaintext []byte
		if cached != nil && cached.off == chunkOff {
			plaintext = cached.data
			cacheUpdate = nil
		} else {
			nn, err := r.src.ReadAt(chunk[:chunkSize], chunkOff)
			if err == io.EOF {
				if int64(nn) != chunkSize {
					err = io.ErrUnexpectedEOF
				} else {
					err = nil
				}
			}
			if err != nil {
				return n, fmt.Errorf("failed to read chunk at offset %d: %w", chunkOff, err)
			}
			nonce := nonceForChunk(chunkIndex)
			if chunkIndex == r.chunks-1 {
				setLastChunkFlag(nonce)
			}
			plaintext, err = r.a.Open(chunk[:0], nonce[:], chunk[:chunkSize], nil)
			if err != nil {
				return n, fmt.Errorf("failed to decrypt and authenticate chunk at offset %d: %w", chunkOff, err)
			}
			cacheUpdate = &cachedChunk{off: chunkOff, data: plaintext}
		}

		plainChunkOff := int(off - chunkIndex*ChunkSize)
		copySize := min(len(plaintext)-plainChunkOff, len(p))
		copy(p, plaintext[plainChunkOff:plainChunkOff+copySize])
		p = p[copySize:]
		off += int64(copySize)
		n += copySize
	}
	if cacheUpdate != nil {
		r.cache.Store(cacheUpdate)
	}
	if off == r.size {
		return n, io.EOF
	}
	return n, nil
}
