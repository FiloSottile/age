// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

import (
	"bytes"
	"encoding/hex"

	"filippo.io/age/internal/testkit"
)

func main() {
	f := testkit.NewTestFile()
	// Reuse the file key and nonce from a previous test vector to avoid
	// bloating the git history with two versions that can't be compressed.
	fileKey, _ := hex.DecodeString("7aa5bdac0e6afeed3dd0a7eccb42af44")
	f.FileKey(fileKey)
	f.VersionLine("v1")
	f.X25519(testkit.TestX25519Identity)
	f.HMAC()
	nonce, _ := hex.DecodeString("c82f71eb82029b77136399e485e879f4")
	f.Nonce(nonce)
	f.PayloadChunk(bytes.Repeat([]byte{0}, 64*1024))
	f.PayloadChunkFinal([]byte{})
	f.Comment("final STREAM chunk can't be empty unless whole payload is empty")
	f.ExpectPayloadFailure()
	f.Generate()
}
