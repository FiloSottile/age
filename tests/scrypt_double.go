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
	f.Scrypt("password", 10)
	f.Scrypt("hunter2", 10)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("scrypt stanzas must be alone in the header")
	f.Generate()
}
