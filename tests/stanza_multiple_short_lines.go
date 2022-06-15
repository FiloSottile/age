// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

import (
	"strings"

	"filippo.io/age/internal/testkit"
)

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.X25519(testkit.TestX25519Recipient)
	f.ArgsLine("stanza")
	f.TextLine(strings.Repeat("A", 32))
	f.TextLine(strings.Repeat("A", 32))
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("a short body line ends the stanza")
	f.Generate()
}
