// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import (
	"encoding/base64"

	"filippo.io/age/internal/testkit"
	"golang.org/x/crypto/curve25519"
)

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	share, _ := curve25519.X25519(f.Rand(32), curve25519.Basepoint)
	f.X25519RecordIdentity(testkit.TestX25519Identity)
	f.X25519Stanza(share, testkit.TestX25519Identity)
	body, _ := f.UnreadLine(), f.UnreadLine()
	f.TextLine("-> X25519 " + base64.RawStdEncoding.EncodeToString(append(share, 0x00)))
	f.TextLine(body)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("a trailing zero is missing from the X25519 share")
	f.Generate()
}
