// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"fmt"
	"os"

	"filippo.io/age"
	"golang.org/x/crypto/ssh/terminal"
)

type LazyScryptIdentity struct {
	Passphrase func() (string, error)
}

var _ age.Identity = &LazyScryptIdentity{}

func (i *LazyScryptIdentity) Type() string {
	return "scrypt"
}

func (i *LazyScryptIdentity) Unwrap(block *age.Stanza) (fileKey []byte, err error) {
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
