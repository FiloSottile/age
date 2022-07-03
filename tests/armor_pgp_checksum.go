// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import (
	"filippo.io/age/internal/testkit"
	"golang.org/x/crypto/openpgp/armor"
)

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.X25519(testkit.TestX25519Recipient)
	f.HMAC()
	f.Payload("age")
	file := f.Bytes()
	f.Buf.Reset()
	w, _ := armor.Encode(&f.Buf, "AGE ENCRYPTED FILE", nil)
	w.Write(file)
	w.Close()
	f.Buf.WriteString("\n")
	f.ExpectArmorFailure()
	f.Generate()
}
