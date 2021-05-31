// Copyright 2021 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// +build !windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func readPassphraseFromTerminal() ([]byte, error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil, fmt.Errorf("opening /dev/tty failed: %v", err)
	}
	defer tty.Close()
	defer fmt.Fprintf(os.Stderr, "\n")
	return term.ReadPassword(int(tty.Fd()))
}
