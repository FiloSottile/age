// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"

	"filippo.io/age"
	"golang.org/x/term"
)

type LazyScryptIdentity struct {
	Passphrase func() (string, error)
}

var _ age.Identity = &LazyScryptIdentity{}

func (i *LazyScryptIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	for _, s := range stanzas {
		if s.Type == "scrypt" && len(stanzas) != 1 {
			return nil, errors.New("an scrypt recipient must be the only one")
		}
	}
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

type EncryptedIdentity struct {
	Contents       []byte
	Passphrase     func() (string, error)
	NoMatchWarning func()

	identities []age.Identity
}

var _ age.Identity = &EncryptedIdentity{}

func (i *EncryptedIdentity) Recipients() ([]age.Recipient, error) {
	if i.identities == nil {
		if err := i.decrypt(); err != nil {
			return nil, err
		}
	}

	return identitiesToRecipients(i.identities)
}

func (i *EncryptedIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	if i.identities == nil {
		if err := i.decrypt(); err != nil {
			return nil, err
		}
	}

	for _, id := range i.identities {
		fileKey, err = id.Unwrap(stanzas)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return fileKey, nil
	}
	i.NoMatchWarning()
	return nil, age.ErrIncorrectIdentity
}

func (i *EncryptedIdentity) decrypt() error {
	d, err := age.Decrypt(bytes.NewReader(i.Contents), &LazyScryptIdentity{i.Passphrase})
	if e := new(age.NoIdentityMatchError); errors.As(err, &e) {
		return fmt.Errorf("identity file is encrypted with age but not with a passphrase")
	}
	if err != nil {
		return fmt.Errorf("failed to decrypt identity file: %v", err)
	}
	i.identities, err = age.ParseIdentities(d)
	return err
}

// readPassphrase reads a passphrase from the terminal. It does not read from a
// non-terminal stdin, so it does not check stdinInUse.
func readPassphrase(prompt string) ([]byte, error) {
	var in, out *os.File
	if runtime.GOOS == "windows" {
		var err error
		in, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		defer in.Close()
		out, err = os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		defer out.Close()
	} else if _, err := os.Stat("/dev/tty"); err == nil {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		defer tty.Close()
		in, out = tty, tty
	} else {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("standard input is not a terminal, and /dev/tty is not available: %v", err)
		}
		in, out = os.Stdin, os.Stderr
	}
	fmt.Fprintf(out, "%s ", prompt)
	// Use CRLF to work around an apparent bug in WSL2's handling of CONOUT$.
	// Only when running a Windows binary from WSL2, the cursor would not go
	// back to the start of the line with a simple LF. Honestly, it's impressive
	// CONIN$ and CONOUT$ even work at all inside WSL2.
	defer fmt.Fprintf(out, "\r\n")
	return term.ReadPassword(int(in.Fd()))
}
