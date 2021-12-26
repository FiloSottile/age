// Copyright 2021 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// This file implements the terminal UI of cmd/age. The rules are:
//
//   - Anything that requires user interaction goes to the terminal,
//     and is erased afterwards if possible. This UI would be possible
//     to replace with a pinentry with no output or UX changes.
//
//   - Everything else goes to standard error with an "age:" prefix.
//     No capitalized initials and no periods at the end.

import (
	"fmt"
	"log"
	"os"
	"runtime"

	"golang.org/x/term"
)

// l is a logger with no prefixes.
var l = log.New(os.Stderr, "", 0)

func printf(format string, v ...interface{}) {
	l.Printf("age: "+format, v...)
}

func errorf(format string, v ...interface{}) {
	l.Printf("age: error: "+format, v...)
	l.Fatalf("age: report unexpected or unhelpful errors at https://filippo.io/age/report")
}

func warningf(format string, v ...interface{}) {
	l.Printf("age: warning: "+format, v...)
}

func errorWithHint(error string, hints ...string) {
	l.Printf("age: error: %s", error)
	for _, hint := range hints {
		l.Printf("age: hint: %s", hint)
	}
	l.Fatalf("age: report unexpected or unhelpful errors at https://filippo.io/age/report")
}

// Terminal escape codes to erase the previous line.
const (
	CUI = "\033["   // Control Sequence Introducer
	CPL = CUI + "F" // Cursor Previous Line
	EL  = CUI + "K" // Erase in Line
	CHA = CUI + "G" // Cursor Horizontal Absolute
)

// readSecret reads a value from the terminal with no echo. The prompt is
// ephemeral. readSecret does not read from a non-terminal stdin, so it does not
// check stdinInUse.
func readSecret(prompt string) ([]byte, error) {
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
	} else if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		in, out = tty, tty
	} else {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("standard input is not a terminal, and /dev/tty is not available: %v", err)
		}
		in, out = os.Stdin, os.Stderr
	}

	fmt.Fprintf(out, "%s ", prompt)

	// First, open a new line (since the return character is not echoed, like
	// the password), which is guaranteed to work everywhere. Then, try to erase
	// the line above with escape codes. (We use CRLF instead of LF to work
	// around an apparent bug in WSL2's handling of CONOUT$. Only when running a
	// Windows binary from WSL2, the cursor would not go back to the start of
	// the line with a simple LF. Honestly, it's impressive CONIN$ and CONOUT$
	// even work at all inside WSL2.)
	defer fmt.Fprintf(out, "\r\n"+CPL+EL)

	return term.ReadPassword(int(in.Fd()))
}

func pluginDisplayMessage(name string) func(string) error {
	return func(message string) error {
		printf("%s plugin: %s", name, message)
		return nil
	}
}

func pluginRequestSecret(name string) func(string, bool) (string, error) {
	return func(message string, _ bool) (string, error) {
		secret, err := readSecret(message)
		if err != nil {
			return "", fmt.Errorf("could not read value for age-plugin-%s: %v", name, err)
		}
		return string(secret), nil
	}
}
