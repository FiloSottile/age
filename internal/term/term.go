package term

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/term"
)

// enableVirtualTerminalProcessing tries to enable virtual terminal processing
// on Windows. If it fails, avoid using escape sequences to prevent weird
// characters being printed to the console.
var enableVirtualTerminalProcessing func(out *os.File) error

// clearLine clears the current line on the terminal, or opens a new line if
// terminal escape codes don't work.
func clearLine(out *os.File) {
	const (
		CUI = "\033["   // Control Sequence Introducer
		CPL = CUI + "F" // Cursor Previous Line
		EL  = CUI + "K" // Erase in Line
	)

	// First, open a new line, which is guaranteed to work everywhere. Then, try
	// to erase the line above with escape codes, if possible.
	//
	// (We use CRLF instead of LF to work around an apparent bug in WSL2's
	// handling of CONOUT$. Only when running a Windows binary from WSL2, the
	// cursor would not go back to the start of the line with a simple LF.
	// Honestly, it's impressive CONIN$ and CONOUT$ work at all inside WSL2.)
	fmt.Fprintf(out, "\r\n")
	if enableVirtualTerminalProcessing == nil || enableVirtualTerminalProcessing(out) == nil {
		fmt.Fprintf(out, CPL+EL)
	}
}

// WithTerminal runs f with the terminal input and output files, if available.
// WithTerminal does not open a non-terminal stdin, so the caller does not need
// to check if stdin is in use.
func WithTerminal(f func(in, out *os.File) error) error {
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

// ReadSecret reads a value from the terminal with no echo. The prompt is ephemeral.
func ReadSecret(prompt string) (s []byte, err error) {
	err = WithTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		defer clearLine(out)
		s, err = term.ReadPassword(int(in.Fd()))
		return err
	})
	return
}

// ReadPublic reads a value from the terminal. The prompt is ephemeral.
func ReadPublic(prompt string) (s []byte, err error) {
	err = WithTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		defer clearLine(out)

		oldState, err := term.MakeRaw(int(in.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(in.Fd()), oldState)

		t := term.NewTerminal(in, "")
		line, err := t.ReadLine()
		s = []byte(line)
		return err
	})
	return
}

// ReadCharacter reads a single character from the terminal with no echo. The
// prompt is ephemeral.
func ReadCharacter(prompt string) (c byte, err error) {
	err = WithTerminal(func(in, out *os.File) error {
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

// IsTerminal returns whether the given file is a terminal.
func IsTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
