// Copyright 2025 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package plugin_test

import (
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// TestParseRecipientNotPlugin checks that the error for a Bech32 string that
// decodes fine but isn't a plugin recipient doesn't end with a nil error.
func TestParseRecipientNotPlugin(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = plugin.ParseRecipient(id.Recipient().String())
	if err == nil || err.Error() != "not a plugin recipient" {
		t.Errorf("unexpected error for a non-plugin recipient: %v", err)
	}
}
