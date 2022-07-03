// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import (
	"strings"

	"filippo.io/age/internal/testkit"
)

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.X25519(testkit.TestX25519Recipient)
	f.HMAC()
	f.Payload("age")
	file := f.Bytes()
	f.Buf.Reset()
	f.BeginArmor("AGE ENCRYPTED FILE")
	f.Body(file)
	f.Base64Padding()
	begin, rest, _ := strings.Cut(string(f.Bytes()), "\n")
	f.Buf.Reset()
	f.TextLine(begin)
	f.Buf.WriteString(rest[:4] + "*" + rest[5:])
	f.EndArmor("AGE ENCRYPTED FILE")
	f.ExpectArmorFailure()
	f.Generate()
}
