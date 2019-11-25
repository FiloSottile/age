// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/FiloSottile/age/internal/age"
	"github.com/FiloSottile/age/internal/format"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type EncryptedSSHIdentity struct {
	pubKey     ssh.PublicKey
	pemBytes   []byte
	passphrase func() ([]byte, error)

	decrypted age.Identity
}

func NewEncryptedSSHIdentity(pubKey ssh.PublicKey, pemBytes []byte, passphrase func() ([]byte, error)) (*EncryptedSSHIdentity, error) {
	switch t := pubKey.Type(); t {
	case "ssh-ed25519", "ssh-rsa":
	default:
		return nil, fmt.Errorf("unsupported SSH key type: %v", t)
	}
	return &EncryptedSSHIdentity{
		pubKey:     pubKey,
		pemBytes:   pemBytes,
		passphrase: passphrase,
	}, nil
}

var _ age.IdentityMatcher = &EncryptedSSHIdentity{}

func (i *EncryptedSSHIdentity) Type() string {
	return i.pubKey.Type()
}

func (i *EncryptedSSHIdentity) Unwrap(block *format.Recipient) (fileKey []byte, err error) {
	if i.decrypted != nil {
		return i.decrypted.Unwrap(block)
	}

	passphrase, err := i.passphrase()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain passphrase: %v", err)
	}
	k, err := ssh.ParseRawPrivateKeyWithPassphrase(i.pemBytes, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SSH key file: %v", err)
	}

	switch k := k.(type) {
	case *ed25519.PrivateKey:
		i.decrypted, err = age.NewSSHEd25519Identity(*k)
	case *rsa.PrivateKey:
		i.decrypted, err = age.NewSSHRSAIdentity(k)
	default:
		return nil, fmt.Errorf("unexpected SSH key type: %T", k)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid SSH key: %v", err)
	}
	if i.decrypted.Type() != i.pubKey.Type() {
		return nil, fmt.Errorf("mismatched SSH key type: got %q, expected %q", i.decrypted.Type(), i.pubKey.Type())
	}

	return i.decrypted.Unwrap(block)
}

func (i *EncryptedSSHIdentity) Matches(block *format.Recipient) error {
	if block.Type != i.Type() {
		return age.ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return fmt.Errorf("invalid %v recipient block", i.Type())
	}
	hash, err := format.DecodeString(block.Args[0])
	if err != nil {
		return fmt.Errorf("failed to parse %v recipient: %v", i.Type(), err)
	}
	if len(hash) != 4 {
		return fmt.Errorf("invalid %v recipient block", i.Type())
	}

	sH := sha256.New()
	sH.Write(i.pubKey.Marshal())
	hh := sH.Sum(nil)
	if !bytes.Equal(hh[:4], hash) {
		return age.ErrIncorrectIdentity
	}
	return nil
}

func passphrasePrompt(name string) func() ([]byte, error) {
	return func() ([]byte, error) {
		fd := int(os.Stdin.Fd())
		if !terminal.IsTerminal(fd) {
			tty, err := os.Open("/dev/tty")
			if err != nil {
				return nil, fmt.Errorf("could not read passphrase for %q: standard input is not a terminal, and opening /dev/tty failed: %v", name, err)
			}
			defer tty.Close()
			fd = int(tty.Fd())
		}
		fmt.Fprintf(os.Stderr, "Enter passphrase for %q: ", name)
		defer fmt.Fprintf(os.Stderr, "\n")
		p, err := terminal.ReadPassword(fd)
		if err != nil {
			return nil, fmt.Errorf("could not read passphrase for %q: %v", name, err)
		}
		return p, nil
	}
}
