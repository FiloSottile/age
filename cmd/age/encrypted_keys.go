// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"filippo.io/age"
	"golang.org/x/term"
)

type LazyScryptIdentity struct {
	Passphrase func() (string, error)
}

var _ age.Identity = &LazyScryptIdentity{}

func (i *LazyScryptIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	if len(stanzas) != 1 || stanzas[0].Type != "scrypt" {
		return nil, age.ErrIncorrectIdentity
	}
	pass, err := i.Passphrase()
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %v", err)
	}
	ii, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, err
	}
	fileKey, err = ii.Unwrap(stanzas)
	if errors.Is(err, age.ErrIncorrectIdentity) {
		// ScryptIdentity returns ErrIncorrectIdentity for an incorrect
		// passphrase, which would lead Decrypt to returning "no identity
		// matched any recipient". That makes sense in the API, where there
		// might be multiple configured ScryptIdentity. Since in cmd/age there
		// can be only one, return a better error message.
		return nil, fmt.Errorf("incorrect passphrase")
	}
	return fileKey, err
}

// readPassphraseFromFD reads a passphrase from a file descriptor.
func readPassphraseFromFD(fd int) ([]byte, error) {
	// readPassphraseFromFD should not be used as an alternative to readPassphrase
	if fd == 0 {
		return nil,fmt.Errorf("refusing to read from STDIN!\n")
	}

	buffer := make([]byte, 1024)
	nBytes, err := syscall.Read(fd, buffer)

	if err != nil {
		return nil, err
	}

	passphrase := make([]byte, nBytes)
	copy(passphrase, buffer)

	return passphrase, nil
}

// readPassphrase reads a passphrase from the terminal. If stdin is not
// connected to a terminal, it tries /dev/tty and fails if that's not available.
// It does not read from a non-terminal stdin, so it does not check stdinInUse.
func readPassphrase() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nil, fmt.Errorf("standard input is not a terminal, and opening /dev/tty failed: %v", err)
		}
		defer tty.Close()
		fd = int(tty.Fd())
	}
	defer fmt.Fprintf(os.Stderr, "\n")
	p, err := term.ReadPassword(fd)
	if err != nil {
		return nil, err
	}
	return p, nil
}
