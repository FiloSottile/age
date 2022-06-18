// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

import "filippo.io/age/internal/testkit"

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.ScryptRecordPassphrase("wrong")
	f.ScryptNoRecordPassphrase("password", 10)
	f.HMAC()
	f.Payload("age")
	f.ExpectNoMatch()
	f.Generate()
}
