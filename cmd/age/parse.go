// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

// stdinInUse is set in main. It's a singleton like os.Stdin.
var stdinInUse bool

func parseRecipient(arg string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(arg, "age1"):
		return age.ParseX25519Recipient(arg)
	case strings.HasPrefix(arg, "ssh-"):
		return agessh.ParseRecipient(arg)
	case strings.HasPrefix(arg, "github:"):
		name := strings.TrimPrefix(arg, "github:")
		return nil, fmt.Errorf(`"github:" recipients were removed from the design.`+"\n"+
			"Instead, use recipient files like\n\n    curl -O https://github.com/%s.keys\n    age -R %s.keys\n\n", name, name)
	}

	return nil, fmt.Errorf("unknown recipient type: %q", arg)
}

func parseRecipientsFile(name string) ([]age.Recipient, error) {
	var f *os.File
	if name == "-" {
		if stdinInUse {
			return nil, fmt.Errorf("standard input is used for multiple purposes")
		}
		stdinInUse = true
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(name)
		if err != nil {
			return nil, fmt.Errorf("failed to open recipient file: %v", err)
		}
		defer f.Close()
	}

	const recipientFileSizeLimit = 16 << 20 // 16 MiB
	const lineLengthLimit = 8 << 10         // 8 KiB, same as sshd(8)
	var recs []age.Recipient
	scanner := bufio.NewScanner(io.LimitReader(f, recipientFileSizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if len(line) > lineLengthLimit {
			return nil, fmt.Errorf("%q: line %d is too long", name, n)
		}
		r, err := parseRecipient(line)
		if err != nil {
			if t, ok := sshKeyType(line); ok {
				// Skip unsupported but valid SSH public keys with a warning.
				log.Printf("Warning: recipients file %q: ignoring unsupported SSH key of type %q at line %d", name, t, n)
				continue
			}
			// Hide the error since it might unintentionally leak the contents
			// of confidential files.
			return nil, fmt.Errorf("%q: malformed recipient at line %d", name, n)
		}
		recs = append(recs, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%q: failed to read recipients file: %v", name, err)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("%q: no recipients found", name)
	}
	return recs, nil
}

func sshKeyType(s string) (string, bool) {
	// TODO: also ignore options? And maybe support multiple spaces and tabs as
	// field separators like OpenSSH?
	fields := strings.Split(s, " ")
	if len(fields) < 2 {
		return "", false
	}
	key, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", false
	}
	k := cryptobyte.String(key)
	var typeLen uint32
	var typeBytes []byte
	if !k.ReadUint32(&typeLen) || !k.ReadBytes(&typeBytes, int(typeLen)) {
		return "", false
	}
	if t := fields[0]; t == string(typeBytes) {
		return t, true
	}
	return "", false
}

// parseIdentitiesFile parses a file that contains age or SSH keys. It returns
// one of *age.X25519Identity, *agessh.RSAIdentity, *agessh.Ed25519Identity, or
// *agessh.EncryptedSSHIdentity.
func parseIdentitiesFile(name string) ([]age.Identity, error) {
	var f *os.File
	if name == "-" {
		if stdinInUse {
			return nil, fmt.Errorf("standard input is used for multiple purposes")
		}
		stdinInUse = true
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(name)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %v", err)
		}
		defer f.Close()
	}

	b := bufio.NewReader(f)
	const pemHeader = "-----BEGIN"
	if peeked, _ := b.Peek(len(pemHeader)); string(peeked) == pemHeader {
		const privateKeySizeLimit = 1 << 14 // 16 KiB
		contents, err := ioutil.ReadAll(io.LimitReader(b, privateKeySizeLimit))
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %v", name, err)
		}
		if len(contents) == privateKeySizeLimit {
			return nil, fmt.Errorf("failed to read %q: file too long", name)
		}
		return parseSSHIdentity(name, contents)
	}

	ids, err := age.ParseIdentities(b)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", name, err)
	}
	return ids, nil
}

func parseSSHIdentity(name string, pemBytes []byte) ([]age.Identity, error) {
	id, err := agessh.ParseIdentity(pemBytes)
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
		i, err := agessh.NewEncryptedSSHIdentity(pubKey, pemBytes, passphrasePrompt)
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
	if name == "-" {
		return nil, fmt.Errorf(`failed to obtain public key for "-" SSH key

Use a file for which the corresponding ".pub" file exists, or convert the private key to a modern format with "ssh-keygen -p -m RFC4716"`)
	}
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
