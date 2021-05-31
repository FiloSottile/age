// Copyright 2021 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// +build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

func readPassphraseFromTerminal() ([]byte, error) {
	conin, err := windows.UTF16PtrFromString("CONIN$")
	if err != nil {
		return nil, err
	}
	tty, err := windows.CreateFile(conin, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("opening CONIN$ failed: %v", err)
	}
	defer windows.CloseHandle(tty)
	defer fmt.Fprintf(os.Stderr, "\n")
	return term.ReadPassword(int(tty))
}
