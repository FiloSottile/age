// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import (
	"encoding/base64"

	"filippo.io/age/internal/testkit"
)

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.Scrypt("password", 10)
	body, _ := base64.RawStdEncoding.DecodeString(f.UnreadLine())
	body[len(body)-1] ^= 0xff
	f.TextLine(base64.RawStdEncoding.EncodeToString(body))
	f.HMAC()
	f.Payload("age")
	f.ExpectNoMatch()
	f.Comment("the ChaCha20Poly1305 authentication tag on the body of the scrypt stanza is wrong")
	f.Generate()
}
