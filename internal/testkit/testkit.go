// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testkit

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age/internal/bech32"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var TestFileKey = []byte("YELLOW SUBMARINE")

var _, TestX25519Identity, _ = bech32.Decode(
	"AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0")

var TestX25519Recipient, _ = curve25519.X25519(TestX25519Identity, curve25519.Basepoint)

type TestFile struct {
	Buf  bytes.Buffer
	rand io.Reader

	streamKey  []byte
	nonce      [12]byte
	payload    bytes.Buffer
	expect     string
	comment    string
	identities []string
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for n := range p {
		p[n] = 0
	}
	return len(p), nil
}

func NewTestFile() *TestFile {
	c, _ := chacha20.NewUnauthenticatedCipher(
		[]byte("TEST RANDOMNESS TEST RANDOMNESS!"), make([]byte, chacha20.NonceSize))
	return &TestFile{rand: cipher.StreamReader{c, zeroReader{}}, expect: "success"}
}

func (f *TestFile) TextLine(s string) {
	f.Buf.WriteString(s)
	f.Buf.WriteString("\n")
}

func (f *TestFile) VersionLine(v string) {
	f.TextLine("age-encryption.org/" + v)
}

func (f *TestFile) ArgsLine(args ...string) {
	f.TextLine(strings.Join(append([]string{"->"}, args...), " "))
}

var b64 = base64.RawStdEncoding.EncodeToString

func (f *TestFile) Body(body []byte) {
	for {
		line := body
		if len(line) > 48 {
			line = line[:48]
		}
		f.TextLine(b64(line))
		body = body[len(line):]
		if len(line) < 48 {
			break
		}
	}
}

func (f *TestFile) Stanza(args []string, body []byte) {
	f.ArgsLine(args...)
	f.Body(body)
}

func (f *TestFile) AEADBody(key, body []byte) {
	aead, _ := chacha20poly1305.New(key)
	f.Body(aead.Seal(nil, make([]byte, chacha20poly1305.NonceSize), body, nil))
}

func (f *TestFile) X25519(identity []byte) {
	id, _ := bech32.Encode("AGE-SECRET-KEY-", identity)
	f.identities = append(f.identities, id)
	recipient, _ := curve25519.X25519(identity, curve25519.Basepoint)
	ephemeral := make([]byte, 32)
	f.rand.Read(ephemeral)
	share, _ := curve25519.X25519(ephemeral, curve25519.Basepoint)
	f.ArgsLine("X25519", b64(share))
	secret, _ := curve25519.X25519(ephemeral, recipient)
	key := make([]byte, 32)
	hkdf.New(sha256.New, secret, append(share, recipient...),
		[]byte("age-encryption.org/v1/X25519")).Read(key)
	f.AEADBody(key, TestFileKey)
}

func (f *TestFile) HMACLine(h []byte) {
	f.TextLine("--- " + b64(h))
}

func (f *TestFile) HMAC() {
	key := make([]byte, 32)
	hkdf.New(sha256.New, TestFileKey, nil, []byte("header")).Read(key)
	h := hmac.New(sha256.New, key)
	h.Write(f.Buf.Bytes())
	h.Write([]byte("---"))
	f.HMACLine(h.Sum(nil))
}

func (f *TestFile) Nonce() {
	nonce := make([]byte, 16)
	f.rand.Read(nonce)
	f.streamKey = make([]byte, 32)
	hkdf.New(sha256.New, TestFileKey, nonce, []byte("payload")).Read(f.streamKey)
	f.Buf.Write(nonce)
}

func (f *TestFile) PayloadChunk(plaintext []byte) {
	f.payload.Write(plaintext)
	aead, _ := chacha20poly1305.New(f.streamKey)
	f.Buf.Write(aead.Seal(nil, f.nonce[:], plaintext, nil))
	f.nonce[10]++
}

func (f *TestFile) PayloadChunkFinal(plaintext []byte) {
	f.payload.Write(plaintext)
	f.nonce[11] = 1
	aead, _ := chacha20poly1305.New(f.streamKey)
	f.Buf.Write(aead.Seal(nil, f.nonce[:], plaintext, nil))
}

func (f *TestFile) Payload(plaintext string) {
	f.Nonce()
	f.PayloadChunkFinal([]byte(plaintext))
}

func (f *TestFile) ExpectHeaderFailure() {
	f.expect = "header failure"
}

func (f *TestFile) ExpectPayloadFailure() {
	f.expect = "payload failure"
}

func (f *TestFile) Comment(c string) {
	f.comment = c
}

func (f *TestFile) Generate() {
	fmt.Printf("expect: %s\n", f.expect)
	if f.expect == "success" {
		fmt.Printf("payload: %x\n", sha256.Sum256(f.payload.Bytes()))
	}
	for _, id := range f.identities {
		fmt.Printf("identity: %s\n", id)
	}
	if f.comment != "" {
		fmt.Printf("comment: %s\n", f.comment)
	}
	fmt.Println()
	io.Copy(os.Stdout, &f.Buf)
}
