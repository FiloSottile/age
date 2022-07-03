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
	f.HMAC()
	f.Payload("age")
	file := f.Bytes()
	f.Buf.Reset()
	f.Buf.Write([]byte("\n\r   \t\n"))
	f.BeginArmor("AGE ENCRYPTED FILE")
	f.Body(file)
	f.Base64Padding()
	f.EndArmor("AGE ENCRYPTED FILE")
	f.Buf.Write([]byte("\n\r   \t\n"))
	f.Comment("whitespace is allowed before and after armored files")
	f.Generate()
}
