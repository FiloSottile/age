// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import (
	"encoding/base64"
	"encoding/hex"

	"filippo.io/age/internal/testkit"
)

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	share, _ := hex.DecodeString("97ba38a135fd5f9137fca3836bfec24340ab03d7ca316b26f482636334a52600")
	f.X25519RecordIdentity(testkit.TestX25519Identity)
	f.X25519Stanza(share, testkit.TestX25519Identity)
	body, _ := f.UnreadLine(), f.UnreadLine()
	f.TextLine("-> X25519 " + base64.RawStdEncoding.EncodeToString(share[:31]))
	f.TextLine(body)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("a trailing zero is missing from the X25519 share")
	f.Generate()
}
