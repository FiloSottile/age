// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

import "filippo.io/age/internal/testkit"

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.X25519(testkit.TestX25519Identity)
	f.FileKey(f.Rand(16))
	f.HMAC()
	f.FileKey(testkit.TestFileKey)
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Generate()
}
