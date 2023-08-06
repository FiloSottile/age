// Copyright 2023 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.20

package plugin

import (
	"crypto/ecdh"
	"fmt"

	"filippo.io/age/internal/bech32"
)

// EncodeX25519Recipient encodes a native X25519 recipient from a
// [crypto/ecdh.X25519] public key. It's meant for plugins that implement
// identities that are compatible with native recipients.
func EncodeX25519Recipient(pk *ecdh.PublicKey) (string, error) {
	if pk.Curve() != ecdh.X25519() {
		return "", fmt.Errorf("wrong ecdh Curve")
	}
	return bech32.Encode("age", pk.Bytes())
}
