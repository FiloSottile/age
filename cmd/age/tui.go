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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age/armor"
	"filippo.io/age/internal/logger"
	"filippo.io/age/internal/term"
	"filippo.io/age/plugin"
)

func printfToTerminal(format string, v ...interface{}) error {
	return term.WithTerminal(func(_, out *os.File) error {
		_, err := fmt.Fprintf(out, "age: "+format+"\n", v...)
		return err
	})
}

var pluginTerminalUI = &plugin.ClientUI{
	DisplayMessage: func(name, message string) error {
		logger.Global.Printf("%s plugin: %s", name, message)
		return nil
	},
	RequestValue: func(name, message string, _ bool) (s string, err error) {
		defer func() {
			if err != nil {
				logger.Global.Warningf("could not read value for age-plugin-%s: %v", name, err)
			}
		}()
		secret, err := term.ReadSecret(message)
		if err != nil {
			return "", err
		}
		return string(secret), nil
	},
	Confirm: func(name, message, yes, no string) (choseYes bool, err error) {
		defer func() {
			if err != nil {
				logger.Global.Warningf("could not read value for age-plugin-%s: %v", name, err)
			}
		}()
		if no == "" {
			message += fmt.Sprintf(" (press enter for %q)", yes)
			_, err := term.ReadSecret(message)
			if err != nil {
				return false, err
			}
			return true, nil
		}
		message += fmt.Sprintf(" (press [1] for %q or [2] for %q)", yes, no)
		for {
			selection, err := term.ReadCharacter(message)
			if err != nil {
				return false, err
			}
			switch selection {
			case '1':
				return true, nil
			case '2':
				return false, nil
			case '\x03': // CTRL-C
				return false, errors.New("user cancelled prompt")
			default:
				logger.Global.Warningf("reading value for age-plugin-%s: invalid selection %q", name, selection)
			}
		}
	},
	WaitTimer: func(name string) {
		logger.Global.Printf("waiting on %s plugin...", name)
	},
}

func bufferTerminalInput(in io.Reader) (io.Reader, error) {
	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(ReaderFunc(func(p []byte) (n int, err error) {
		if bytes.Contains(buf.Bytes(), []byte(armor.Footer+"\n")) {
			return 0, io.EOF
		}
		return in.Read(p)
	})); err != nil {
		return nil, err
	}
	return buf, nil
}

type ReaderFunc func(p []byte) (n int, err error)

func (f ReaderFunc) Read(p []byte) (n int, err error) { return f(p) }
