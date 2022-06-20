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
	body := f.UnreadLine()
	f.TextLine(testkit.NotCanonicalBase64(body))
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("the base64 encoding of the share is not canonical")
	f.Generate()
}
