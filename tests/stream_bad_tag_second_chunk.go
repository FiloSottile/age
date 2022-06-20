// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import "filippo.io/age/internal/testkit"

func main() {
	f := testkit.NewTestFile()
	f.FileKey(testkit.LargeTestFileKey)
	f.VersionLine("v1")
	f.X25519(testkit.TestX25519Identity)
	f.HMAC()
	f.Nonce(testkit.LargeTestNonce)
	f.PayloadChunk(testkit.LargeTestFirstChunk)
	f.PayloadChunkFinal([]byte("age"))
	file := f.Buf.Bytes()
	f.Buf.Reset()
	file[len(file)-1] ^= 0b0010_0000
	f.Buf.Write(file)
	f.ExpectPartialPayload(64 * 1024)
	f.Generate()
}
