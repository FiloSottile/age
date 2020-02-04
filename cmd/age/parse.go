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

	"filippo.io/age/internal/age"
	"golang.org/x/crypto/ssh"
)

func parseRecipient(arg string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(arg, "age1"):
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
	if sshErr, ok := err.(*ssh.PassphraseMissingError); ok {
		pubKey := sshErr.PublicKey
		if pubKey == nil {
			pubKey, err = readPubFile(name)
			if err != nil {
				return nil, err
			}
		}
		passphrasePrompt := func() ([]byte, error) {
			fmt.Fprintf(os.Stderr, "Enter passphrase for %q: ", name)
			pass, err := readPassphrase()
			if err != nil {
				return nil, fmt.Errorf("could not read passphrase for %q: %v", name, err)
			}
			return pass, nil
		}
		i, err := NewEncryptedSSHIdentity(pubKey, pemBytes, passphrasePrompt)
		if err != nil {
			return nil, err
		}
		return []age.Identity{i}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH identity in %q: %v", name, err)
	}

	return []age.Identity{id}, nil
}

func readPubFile(name string) (ssh.PublicKey, error) {
	f, err := os.Open(name + ".pub")
	if err != nil {
		return nil, fmt.Errorf(`failed to obtain public key for %q SSH key: %v

    Ensure %q exists, or convert the private key %q to a modern format with "ssh-keygen -p -m RFC4716"`, name, err, name+".pub", name)
	}
	defer f.Close()
	contents, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", name+".pub", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(contents)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %v", name+".pub", err)
	}
	return pubKey, nil
}
