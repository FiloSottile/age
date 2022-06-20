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
	f.ScryptRecordPassphrase("password")
	f.ScryptNoRecordPassphraseWithSalt("password", 10, nil)
	body, args := f.UnreadLine(), f.UnreadArgsLine()
	f.ArgsLine(args[0], args[2])
	f.TextLine(body)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Generate()
}
