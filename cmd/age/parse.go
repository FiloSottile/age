// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/FiloSottile/age/internal/age"
)

func parseRecipient(arg string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(arg, "pubkey:"):
		return age.ParseX25519Recipient(arg)
	case strings.HasPrefix(arg, "ssh-"):
		return age.ParseSSHRecipient(arg)
	}

	return nil, fmt.Errorf("unknown recipient type: %q", arg)
}

const privateKeySizeLimit = 1 << 24 // 16 MiB

func parseIdentitiesFile(name string) ([]age.Identity, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	contents, err := ioutil.ReadAll(io.LimitReader(f, privateKeySizeLimit))
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", name, err)
	}
	if len(contents) == privateKeySizeLimit {
		return nil, fmt.Errorf("failed to read %q: file too long", name)
	}

	var ids []age.Identity
	var ageParsingError error
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "-----BEGIN") {
			return parseSSHIdentity(name, contents)
		}
		if ageParsingError != nil {
			continue
		}
		i, err := age.ParseX25519Identity(line)
		if err != nil {
			ageParsingError = fmt.Errorf("malformed secret keys file %q: %v", name, err)
			continue
		}
		ids = append(ids, i)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", name, err)
	}
	if ageParsingError != nil {
		return nil, ageParsingError
	}

	if len(ids) == 0 {
		return nil, fmt.Errorf("no secret keys found in %q", name)
	}
	return ids, nil
}

func parseSSHIdentity(name string, pemBytes []byte) ([]age.Identity, error) {
	id, err := age.ParseSSHIdentity(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("malformed SSH identity in %q: %v", name, err)
	}

	return []age.Identity{id}, nil
}
