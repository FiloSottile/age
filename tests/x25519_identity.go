// Copyright 2022 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

import (
	"crypto/sha256"
	"encoding/base64"

	"filippo.io/age/internal/testkit"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func main() {
	f := testkit.NewTestFile()
	f.VersionLine("v1")
	f.X25519RecordIdentity(testkit.TestX25519Identity)
	share := make([]byte, curve25519.PointSize)
	f.ArgsLine("X25519", base64.RawStdEncoding.EncodeToString(share))
	secret := make([]byte, curve25519.PointSize)
	key := make([]byte, 32)
	hkdf.New(sha256.New, secret, append(share, testkit.TestX25519Recipient...),
		[]byte("age-encryption.org/v1/X25519")).Read(key)
	f.AEADBody(key, testkit.TestFileKey)
	f.HMAC()
	f.Payload("age")
	f.ExpectHeaderFailure()
	f.Comment("the X25519 share is a low-order point, so the shared secret is the disallowed all-zero value")
	f.Generate()
}
