// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

import "filippo.io/age/internal/testkit"

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	// Hardcoded because it would be too slow to regenerate every time.
	// f.Scrypt("password", 23)
	f.ArgsLine("scrypt", "rF0/NwblUHHTpgQgRpe5CQ", "23")
	f.TextLine("qW9eVsT0NVb/Vswtw8kPIxUnaYmm9Px1dYmq2+4+qZA")
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("work factor is very high, would take a long time to compute")
	f.Generate()
}
