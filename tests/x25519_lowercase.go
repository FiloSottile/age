// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import "filippo.io/age/internal/testkit"

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.X25519(testkit.TestX25519Recipient)
	body, args := f.UnreadLine(), f.UnreadArgsLine()
	f.ArgsLine("x25519", args[1])
	f.TextLine(body)
	f.HMAC()
	f.Payload("age")
	f.ExpectNoMatch()
	f.Comment("the first argument in the X25519 stanza is lowercase")
	f.Generate()
}
