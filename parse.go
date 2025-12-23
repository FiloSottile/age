// Copyright 2021 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// ParseIdentities parses a file with one or more private key encodings, one per
// line. Empty lines and lines starting with "#" are ignored.
//
// This is the same syntax as the private key files accepted by the CLI, except
// the CLI also accepts SSH private keys, which are not recommended for the
// average application, and plugins, which involve invoking external programs.
//
// Currently, all returned values are of type *[X25519Identity] or
// *[HybridIdentity], but different types might be returned in the future.
func ParseIdentities(f io.Reader) ([]Identity, error) {
	const privateKeySizeLimit = 1 << 24 // 16 MiB
	var ids []Identity
	scanner := bufio.NewScanner(io.LimitReader(f, privateKeySizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !utf8.ValidString(line) {
			return nil, fmt.Errorf("identities file is not valid UTF-8")
		}
		i, err := parseIdentity(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		ids = append(ids, i)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read identities file: %v", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities found")
	}
	return ids, nil
}

func parseIdentity(arg string) (Identity, error) {
	switch {
	case strings.HasPrefix(arg, "AGE-SECRET-KEY-1"):
		return ParseX25519Identity(arg)
	case strings.HasPrefix(arg, "AGE-SECRET-KEY-PQ-1"):
		return ParseHybridIdentity(arg)
	default:
		return nil, fmt.Errorf("unknown identity type: %q", arg)
	}
}

// ParseRecipients parses a file with one or more public key encodings, one per
// line. Empty lines and lines starting with "#" are ignored.
//
// This is the same syntax as the recipients files accepted by the CLI, except
// the CLI also accepts SSH recipients, which are not recommended for the
// average application, tagged recipients, which have different privacy
// properties, and plugins, which involve invoking external programs.
//
// Currently, all returned values are of type *[X25519Recipient] or
// *[HybridRecipient] but different types might be returned in the future.
func ParseRecipients(f io.Reader) ([]Recipient, error) {
	const recipientFileSizeLimit = 1 << 24 // 16 MiB
	var recs []Recipient
	scanner := bufio.NewScanner(io.LimitReader(f, recipientFileSizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !utf8.ValidString(line) {
			return nil, fmt.Errorf("recipients file is not valid UTF-8")
		}
		r, err := parseRecipient(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		recs = append(recs, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read recipients file: %v", err)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("no recipients found")
	}
	return recs, nil
}

func parseRecipient(arg string) (Recipient, error) {
	switch {
	case strings.HasPrefix(arg, "age1pq1"):
		return ParseHybridRecipient(arg)
	case strings.HasPrefix(arg, "age1"):
		return ParseX25519Recipient(arg)
	default:
		return nil, fmt.Errorf("unknown recipient type: %q", arg)
	}
}
