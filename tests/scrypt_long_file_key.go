// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import "filippo.io/age/internal/testkit"

func main() {
	f := testkit.NewTestFile()
	f.FileKey([]byte("A LONGER YELLOW SUBMARINE"))
	f.VersionLine("v1")
	f.Scrypt("password", 10)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("the file key must be checked to be 16 bytes before decrypting it")
	f.Generate()
}
