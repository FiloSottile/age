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
	fileKey, _ := hex.DecodeString("5085919e0d59b19d6cbd00330f03861c")
	f.FileKey(fileKey)
	f.VersionLine("v1")
	f.X25519(testkit.TestX25519Identity)
	f.HMAC()
	nonce, _ := hex.DecodeString("32521791a6f22e11637fb69ead3f2d5f")
	f.Nonce(nonce)
	f.PayloadChunkFinal(bytes.Repeat([]byte{0}, 64*1024))
	f.Generate()
}
