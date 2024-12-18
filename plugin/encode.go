// Copyright 2023 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package plugin

import (
	"fmt"
	"strings"

	"filippo.io/age/internal/bech32"
)

// EncodeIdentity encodes a plugin identity string for a plugin with the given
// name. If the name is invalid, it returns an empty string.
func EncodeIdentity(name string, data []byte) string {
	if !validPluginName(name) {
		return ""
	}
	s, _ := bech32.Encode("AGE-PLUGIN-"+strings.ToUpper(name)+"-", data)
	return s
}

// ParseIdentity decodes a plugin identity string. It returns the plugin name
// in lowercase and the encoded data.
func ParseIdentity(s string) (name string, data []byte, err error) {
	hrp, data, err := bech32.Decode(s)
	if err != nil {
		return "", nil, fmt.Errorf("invalid identity encoding: %v", err)
	}
	if !strings.HasPrefix(hrp, "AGE-PLUGIN-") || !strings.HasSuffix(hrp, "-") {
		return "", nil, fmt.Errorf("not a plugin identity: %v", err)
	}
	name = strings.TrimSuffix(strings.TrimPrefix(hrp, "AGE-PLUGIN-"), "-")
	name = strings.ToLower(name)
	if !validPluginName(name) {
		return "", nil, fmt.Errorf("invalid plugin name: %q", name)
	}
	return name, data, nil
}

// EncodeRecipient encodes a plugin recipient string for a plugin with the given
// name. If the name is invalid, it returns an empty string.
func EncodeRecipient(name string, data []byte) string {
	if !validPluginName(name) {
		return ""
	}
	s, _ := bech32.Encode("age1"+strings.ToLower(name), data)
	return s
}

// ParseRecipient decodes a plugin recipient string. It returns the plugin name
// in lowercase and the encoded data.
func ParseRecipient(s string) (name string, data []byte, err error) {
	hrp, data, err := bech32.Decode(s)
	if err != nil {
		return "", nil, fmt.Errorf("invalid recipient encoding: %v", err)
	}
	if !strings.HasPrefix(hrp, "age1") {
		return "", nil, fmt.Errorf("not a plugin recipient: %v", err)
	}
	name = strings.TrimPrefix(hrp, "age1")
	if !validPluginName(name) {
		return "", nil, fmt.Errorf("invalid plugin name: %q", name)
	}
	return name, data, nil
}

func validPluginName(name string) bool {
	if name == "" {
		return false
	}
	allowed := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-._"
	for _, r := range name {
		if !strings.ContainsRune(allowed, r) {
			return false
		}
	}
	return true
}
