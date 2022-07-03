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

// See base64finl in RFC 7468.
//   ; ...AB= <EOL> = <EOL> is not good, but is valid

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.X25519(testkit.TestX25519Recipient)
	f.HMAC()
	f.Payload("age12")
	file := f.Bytes()
	f.Buf.Reset()
	f.BeginArmor("AGE ENCRYPTED FILE")
	f.Body(file)
	f.Base64Padding()
	line := f.UnreadLine()
	if !strings.Contains(line, "==") {
		panic("need two padding characters")
	}
	line = strings.Replace(line, "==", "=\n=", 1)
	f.TextLine(line)
	f.EndArmor("AGE ENCRYPTED FILE")
	f.ExpectArmorFailure()
	f.Generate()
}
