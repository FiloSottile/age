// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	_log "log"
	"os"

	"filippo.io/age/internal/age"
	"golang.org/x/crypto/ssh/terminal"
)

type multiFlag []string

func (f *multiFlag) String() string { return fmt.Sprint(*f) }

func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	_log.SetFlags(0)

	var (
		outFlag                          string
		decryptFlag, armorFlag, passFlag bool
		recipientFlags, identityFlags    multiFlag
	)

	flag.BoolVar(&decryptFlag, "d", false, "decrypt the input")
	flag.BoolVar(&decryptFlag, "decrypt", false, "decrypt the input")
	flag.BoolVar(&passFlag, "p", false, "use a passphrase")
	flag.BoolVar(&passFlag, "passphrase", false, "use a passphrase")
	flag.StringVar(&outFlag, "o", "", "output to `FILE` (default stdout)")
	flag.BoolVar(&armorFlag, "a", false, "generate an armored file")
	flag.BoolVar(&armorFlag, "armor", false, "generate an armored file")
	flag.Var(&recipientFlags, "r", "recipient (can be repeated)")
	flag.Var(&recipientFlags, "recipient", "recipient (can be repeated)")
	flag.Var(&identityFlags, "i", "identity (can be repeated)")
	flag.Var(&identityFlags, "identity", "identity (can be repeated)")
	flag.Parse()

	if flag.NArg() > 1 {
		logFatalf("Error: too many arguments.\n" +
			"age accepts a single optional argument for the input file.")
	}
	switch {
	case decryptFlag:
		if armorFlag {
			logFatalf("Error: -a/--armor can't be used with -d/--decrypt.\n" +
				"Note that armored files are detected automatically.")
		}
		if passFlag {
			logFatalf("Error: -p/--passphrase can't be used with -d/--decrypt.\n" +
				"Note that password protected files are detected automatically.")
		}
		if len(recipientFlags) > 0 {
			logFatalf("Error: -r/--recipient can't be used with -d/--decrypt.\n" +
				"Did you mean to use -i/--identity to specify a private key?")
		}
	default: // encrypt
		if len(identityFlags) > 0 {
			logFatalf("Error: -i/--identity can't be used in encryption mode.\n" +
				"Did you forget to specify -d/--decrypt?")
		}
		if len(recipientFlags) == 0 && !passFlag {
			logFatalf("Error: missing recipients.\n" +
				"Did you forget to specify -r/--recipient or -p/--passphrase?")
		}
		if len(recipientFlags) > 0 && passFlag {
			logFatalf("Error: -p/--passphrase can't be combined with -r/--recipient.")
		}
	}

	var in, out io.ReadWriter = os.Stdin, os.Stdout
	if name := flag.Arg(0); name != "" && name != "-" {
		f, err := os.Open(name)
		if err != nil {
			logFatalf("Error: failed to open input file %q: %v", name, err)
		}
		defer f.Close()
		in = f
	} else {
		stdinInUse = true
	}
	if name := outFlag; name != "" && name != "-" {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
		if err != nil {
			logFatalf("Error: failed to open output file %q: %v", name, err)
		}
		defer f.Close()
		out = f
	} else if terminal.IsTerminal(int(os.Stdout.Fd())) && !decryptFlag {
		if armorFlag {
			// If the output will go to a TTY, and it will be armored, buffer it
			// up so it doesn't get in the way of typing the input.
			buf := &bytes.Buffer{}
			defer func() { io.Copy(os.Stdout, buf) }()
			out = buf
		} else if name != "-" {
			// If the output wouldn't be armored, refuse to send binary to the
			// terminal unless explicitly requested with "-o -".
			logFatalf("Error: refusing to output binary to the terminal.\n" +
				`Did you mean to use -a/--armor? Force with "-o -".`)
		}
	}

	switch {
	case decryptFlag:
		decrypt(identityFlags, in, out)
	case passFlag:
		pass, err := passphrasePrompt()
		if err != nil {
			logFatalf("Error: %v", err)
		}
		encryptPass(pass, in, out, armorFlag)
	default:
		encryptKeys(recipientFlags, in, out, armorFlag)
	}
}

func passphrasePrompt() (string, error) {
	fmt.Fprintf(os.Stderr, "Enter passphrase: ")
	pass, err := readPassphrase()
	if err != nil {
		return "", fmt.Errorf("could not read passphrase: %v", err)
	}
	return string(pass), nil
}

func encryptKeys(keys []string, in io.Reader, out io.Writer, armor bool) {
	var recipients []age.Recipient
	for _, arg := range keys {
		r, err := parseRecipient(arg)
		if err != nil {
			logFatalf("Error: %v", err)
		}
		recipients = append(recipients, r)
	}
	encrypt(recipients, in, out, armor)
}

func encryptPass(pass string, in io.Reader, out io.Writer, armor bool) {
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		logFatalf("Error: %v", err)
	}
	encrypt([]age.Recipient{r}, in, out, armor)
}

func encrypt(recipients []age.Recipient, in io.Reader, out io.Writer, armor bool) {
	ageEncrypt := age.Encrypt
	if armor {
		ageEncrypt = age.EncryptWithArmor
	}
	w, err := ageEncrypt(out, recipients...)
	if err != nil {
		logFatalf("Error: %v", err)
	}
	if _, err := io.Copy(w, in); err != nil {
		logFatalf("Error: %v", err)
	}
	if err := w.Close(); err != nil {
		logFatalf("Error: %v", err)
	}
}

func decrypt(keys []string, in io.Reader, out io.Writer) {
	identities := []age.Identity{
		// If there is an scrypt recipient (it will have to be the only one and)
		// this identity will be invoked.
		&LazyScryptIdentity{passphrasePrompt},
	}

	// TODO: use the default location if no arguments are provided:
	// os.UserConfigDir()/age/keys.txt, ~/.ssh/id_rsa, ~/.ssh/id_ed25519
	for _, name := range keys {
		ids, err := parseIdentitiesFile(name)
		if err != nil {
			logFatalf("Error: %v", err)
		}
		identities = append(identities, ids...)
	}

	r, err := age.Decrypt(in, identities...)
	if err != nil {
		logFatalf("Error: %v", err)
	}
	if _, err := io.Copy(out, r); err != nil {
		logFatalf("Error: %v", err)
	}
}

func logFatalf(format string, v ...interface{}) {
	_log.Printf(format, v...)
	_log.Fatalf("[ Did age not do what you expected? Could an error be more useful?" +
		" Tell us: https://filippo.io/age/report ]")
}
