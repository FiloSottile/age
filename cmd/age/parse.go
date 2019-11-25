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
	"golang.org/x/crypto/ssh"
)

func parseRecipient(arg string) ([]age.Recipient, error) {
	var parsingError error

	switch {
	case strings.HasPrefix(arg, "pubkey:"):
		r := make([]age.Recipient, 1)
		r[0], parsingError = age.ParseX25519Recipient(arg)
		return r, parsingError
	case strings.HasPrefix(arg, "ssh-"):
		r := make([]age.Recipient, 1)
		r[0], parsingError = age.ParseSSHRecipient(arg)
		return r, parsingError
	}

	return parseRecipientFile(arg)
}

const recipientFileSizeLimit = 1 << 24 // 16 MiB

func parseRecipientFile(arg string) ([]age.Recipient, error) {
	f, err := os.Open(arg)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	contents, err := ioutil.ReadAll(io.LimitReader(f, recipientFileSizeLimit))
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", arg, err)
	}
	if len(contents) == recipientFileSizeLimit {
		return nil, fmt.Errorf("failed to read %q: file too long", arg)
	}

	var recipients []age.Recipient
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "pubkey:"):
			newRecipient, err := age.ParseX25519Recipient(line)
			if err != nil {
				return nil, fmt.Errorf("failed to parse x25519 key line %q", err)
			}
			recipients = append(recipients, newRecipient)

		case strings.HasPrefix(line, "# pubkey:"): //targets age-produced key format
			newRecipient, err := age.ParseX25519Recipient(strings.TrimLeft(line, "# "))
			if err != nil {
				return nil, fmt.Errorf("failed to parse age key line %q", err)
			}
			recipients = append(recipients, newRecipient)

		case strings.HasPrefix(line, "ssh-"):
			newRecipient, err := age.ParseSSHRecipient(line)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ssh key line %q", err)
			}
			recipients = append(recipients, newRecipient)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", arg, err)
	}

	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients found in file %q", arg)
	}

	return recipients, nil
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
	if sshErr, ok := err.(*ssh.PassphraseNeededError); ok {
		pubKey := sshErr.PublicKey
		if pubKey == nil {
			pubKey, err = readPubFile(name)
			if err != nil {
				return nil, err
			}
		}
		i, err := NewEncryptedSSHIdentity(pubKey, pemBytes, passphrasePrompt(name))
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
