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
	f.X25519RecordIdentity(f.Rand(32))
	f.X25519NoRecordIdentity(testkit.TestX25519Identity)
	f.Scrypt("password", 10)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("scrypt stanzas must be alone in the header")
	f.Generate()
}
