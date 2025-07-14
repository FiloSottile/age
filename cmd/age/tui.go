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
	"fmt"
	"io"
	"os"

	"filippo.io/age/armor"
	"filippo.io/age/internal/term"
	"filippo.io/age/plugin"
)

func printfToTerminal(format string, v ...interface{}) error {
	return term.WithTerminal(func(_, out *os.File) error {
		_, err := fmt.Fprintf(out, "age: "+format+"\n", v...)
		return err
	})
}

var pluginTerminalUI = plugin.NewClientUI()

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
