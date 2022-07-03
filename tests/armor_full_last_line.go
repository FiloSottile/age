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
	f.Payload("age age age age age age age age age age ")
	file := f.Bytes()
	f.Buf.Reset()
	f.BeginArmor("AGE ENCRYPTED FILE")
	if len(file)%48 != 0 {
		println(len(file) % 48)
		panic("last line is not full")
	}
	f.Body(file)
	f.UnreadLine() // Body leaves an empty line, PEM doesn't.
	f.EndArmor("AGE ENCRYPTED FILE")
	f.Generate()
}
