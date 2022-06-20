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
	f.X25519RecordIdentity(testkit.TestX25519Identity)
	share := make([]byte, 32)
	f.X25519Stanza(share, testkit.TestX25519Identity)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("the X25519 share is a low-order point, so the shared secret is the disallowed all-zero value")
	f.Generate()
}
