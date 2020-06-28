// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"fmt"

	"filippo.io/age/internal/age"
	"filippo.io/age/internal/format"
)

type LazyScryptIdentity struct {
	Passphrase func() ([]byte, error)
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
