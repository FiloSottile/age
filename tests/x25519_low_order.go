// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

import "filippo.io/age/internal/testkit"

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.X25519RecordIdentity(testkit.TestX25519Identity)
	// Point of order 8 on Curve25519, chosen to be the least likely to be
	// flagged by hardcoded list exclusions.
	share := []byte{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0,
		0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
		0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0xd7}
	f.X25519Stanza(share, testkit.TestX25519Identity)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("the X25519 share is a low-order point, so the shared secret" +
		"is the disallowed all-zero value")
	f.Generate()
}
