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
	"log"
	"os"
	"runtime"

	"filippo.io/age/armor"
	"filippo.io/age/plugin"
	"golang.org/x/term"
)

// l is a logger with no prefixes.
var l = log.New(os.Stderr, "", 0)

func printf(format string, v ...interface{}) {
	l.Printf("age: "+format, v...)
}

func errorf(format string, v ...interface{}) {
	l.Printf("age: error: "+format, v...)
	l.Printf("age: report unexpected or unhelpful errors at https://filippo.io/age/report")
	exit(1)
}

func warningf(format string, v ...interface{}) {
	l.Printf("age: warning: "+format, v...)
}

func errorWithHint(error string, hints ...string) {
	l.Printf("age: error: %s", error)
	for _, hint := range hints {
		l.Printf("age: hint: %s", hint)
	}
	l.Printf("age: report unexpected or unhelpful errors at https://filippo.io/age/report")
	exit(1)
}

// If testOnlyPanicInsteadOfExit is true, exit will set testOnlyDidExit and
// panic instead of calling os.Exit. This way, the wrapper in TestMain can
// recover the panic and return the exit code only if it was originated in exit.
var testOnlyPanicInsteadOfExit bool
var testOnlyDidExit bool

func exit(code int) {
	if testOnlyPanicInsteadOfExit {
		testOnlyDidExit = true
		panic(code)
	}
	os.Exit(code)
}

// clearLine clears the current line on the terminal, or opens a new line if
// terminal escape codes don't work.
func clearLine(out io.Writer) {
	const (
		CUI = "\033["   // Control Sequence Introducer
		CPL = CUI + "F" // Cursor Previous Line
		EL  = CUI + "K" // Erase in Line
	)

	// First, open a new line, which is guaranteed to work everywhere. Then, try
	// to erase the line above with escape codes.
	//
	// (We use CRLF instead of LF to work around an apparent bug in WSL2's
	// handling of CONOUT$. Only when running a Windows binary from WSL2, the
	// cursor would not go back to the start of the line with a simple LF.
	// Honestly, it's impressive CONIN$ and CONOUT$ work at all inside WSL2.)
	fmt.Fprintf(out, "\r\n"+CPL+EL)
}

// withTerminal runs f with the terminal input and output files, if available.
// withTerminal does not open a non-terminal stdin, so the caller does not need
// to check stdinInUse.
func withTerminal(f func(in, out *os.File) error) error {
	if runtime.GOOS == "windows" {
		in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer out.Close()
		return f(in, out)
	} else if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		return f(tty, tty)
	} else if term.IsTerminal(int(os.Stdin.Fd())) {
		return f(os.Stdin, os.Stdin)
	} else {
		return fmt.Errorf("standard input is not a terminal, and /dev/tty is not available: %v", err)
	}
}

func printfToTerminal(format string, v ...interface{}) error {
	return withTerminal(func(_, out *os.File) error {
		_, err := fmt.Fprintf(out, "age: "+format+"\n", v...)
		return err
	})
}

// readSecret reads a value from the terminal with no echo. The prompt is ephemeral.
func readSecret(prompt string) (s []byte, err error) {
	err = withTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		defer clearLine(out)
		s, err = term.ReadPassword(int(in.Fd()))
		return err
	})
	return
}

// readCharacter reads a single character from the terminal with no echo. The
// prompt is ephemeral.
func readCharacter(prompt string) (c byte, err error) {
	err = withTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		defer clearLine(out)

		oldState, err := term.MakeRaw(int(in.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(in.Fd()), oldState)

		b := make([]byte, 1)
		if _, err := in.Read(b); err != nil {
			return err
		}

		c = b[0]
		return nil
	})
	return
}

var pluginTerminalUI = &plugin.ClientUI{
	DisplayMessage: func(name, message string) error {
		printf("%s plugin: %s", name, message)
		return nil
	},
	RequestValue: func(name, message string, _ bool) (s string, err error) {
		defer func() {
			if err != nil {
				warningf("could not read value for age-plugin-%s: %v", name, err)
			}
		}()
		secret, err := readSecret(message)
		if err != nil {
			return "", err
		}
		return string(secret), nil
	},
	Confirm: func(name, message, yes, no string) (choseYes bool, err error) {
		defer func() {
			if err != nil {
				warningf("could not read value for age-plugin-%s: %v", name, err)
			}
		}()
		if no == "" {
			message += fmt.Sprintf(" (press enter for %q)", yes)
			_, err := readSecret(message)
			if err != nil {
				return false, err
			}
			return true, nil
		}
		message += fmt.Sprintf(" (press [1] for %q or [2] for %q)", yes, no)
		for {
			selection, err := readCharacter(message)
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
				warningf("reading value for age-plugin-%s: invalid selection %q", name, selection)
			}
		}
	},
	WaitTimer: func(name string) {
		printf("waiting on %s plugin...", name)
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
