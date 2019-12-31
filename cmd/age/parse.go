// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"filippo.io/age/internal/age"
	"golang.org/x/crypto/ssh"
)

func parseRecipient(arg string) ([]age.Recipient, error) {

	switch {
	case strings.HasPrefix(arg, "age1"):
		r, err := age.ParseX25519Recipient(arg)
		return []age.Recipient{r}, err
	case strings.HasPrefix(arg, "ssh-"):
		r, err := age.ParseSSHRecipient(arg)
		return []age.Recipient{r}, err
	case strings.HasPrefix(arg, "github:"):
		return parseGithubRecipient(arg)
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
	if sshErr, ok := err.(*ssh.PassphraseNeededError); ok {
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

func parseGithubRecipient(s string) ([]age.Recipient, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, errors.New("Invalid github recipient format")
	}

	res, err := http.Get("https://api.github.com/users/" + url.PathEscape(parts[1]) + "/keys")
	if err != nil {
		return nil, fmt.Errorf("Github API request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Github returned HTTP status %d", res.StatusCode)
	}

	type GithubKey struct {
		ID  uint64 `json:"id"`
		Key string `json:"key"`
	}

	var parsedKeys []GithubKey

	err = json.NewDecoder(res.Body).Decode(&parsedKeys)
	if err != nil {
		return nil, fmt.Errorf("Could not parse Github API response: %w", err)
	}

	var recipients []age.Recipient
	for _, ghKey := range parsedKeys {
		k, err := age.ParseSSHRecipient(ghKey.Key)
		if err != nil {
			logFatalf("Unable to parse Github key: %s", err)
		}
		recipients = append(recipients, k)
	}

	if len(recipients) > 0 {
		fmt.Printf("Encrypting with %d keys from Github\n", len(recipients))
		return recipients, nil
	}
	return nil, errors.New("No Github keys found")
}
