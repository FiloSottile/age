// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

import (
	"bytes"

	"filippo.io/age/internal/testkit"
)

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.X25519(testkit.TestX25519Identity)
	hdr := f.Buf.Bytes()
	f.Buf.Reset()
	f.Buf.Write(bytes.Replace(hdr, []byte("\n"), []byte("\r\n"), -1))
	f.HMAC()
	f.Buf.WriteString(f.UnreadLine() + "\r\n")
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("lines in the header end with CRLF instead of LF")
	f.Generate()
}
