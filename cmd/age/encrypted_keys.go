// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"os"

	"filippo.io/age/internal/age"
	"filippo.io/age/internal/format"
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
	if len(block.Args) < 1 {
		return fmt.Errorf("invalid %v recipient block", i.Type())
	}

	if block.Args[0] != age.SSHFingerprint(i.pubKey) {
		return age.ErrIncorrectIdentity
	}
	return nil
}

type LazyScryptIdentity struct {
	Passphrase func() (string, error)
}

var _ age.Identity = &LazyScryptIdentity{}

func (i *LazyScryptIdentity) Type() string {
	return "scrypt"
}

func (i *LazyScryptIdentity) Unwrap(block *format.Recipient) (fileKey []byte, err error) {
	pass, err := i.Passphrase()
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %v", err)
	}
	ii, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, err
	}
	fileKey, err = ii.Unwrap(block)
	if err == age.ErrIncorrectIdentity {
		// The API will just ignore the identity if the passphrase is wrong, and
		// move on, eventually returning "no identity matched a recipient".
		// Since we only supply one identity from the CLI, make it a fatal
		// error with a better message.
		return nil, fmt.Errorf("incorrect passphrase")
	}
	return fileKey, err
}

// stdinInUse is set in main. It's a singleton like os.Stdin.
var stdinInUse bool

func readPassphrase() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !terminal.IsTerminal(fd) || stdinInUse {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nil, fmt.Errorf("standard input is not available or not a terminal, and opening /dev/tty failed: %v", err)
		}
		defer tty.Close()
		fd = int(tty.Fd())
	}
	defer fmt.Fprintf(os.Stderr, "\n")
	p, err := terminal.ReadPassword(fd)
	if err != nil {
		return nil, err
	}
	return p, nil
}
