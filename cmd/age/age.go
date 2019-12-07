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
	"log"
	"os"

	"github.com/FiloSottile/age/internal/age"
	"golang.org/x/crypto/ssh/terminal"
)

type multiFlag []string

func (f *multiFlag) String() string { return fmt.Sprint(*f) }

func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	log.SetFlags(0)

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
		log.Printf("Error: too many arguments.")
		log.Fatalf("age accepts a single optional argument for the input file.")
	}
	switch {
	case decryptFlag:
		if armorFlag {
			log.Printf("Error: -a/--armor can't be used with -d/--decrypt.")
			log.Fatalf("Note that armored files are detected automatically.")
		}
		if len(recipientFlags) > 0 {
			log.Printf("Error: -r/--recipient can't be used with -d/--decrypt.")
			log.Fatalf("Did you mean to use -i/--identity to specify a private key?")
		}
	default: // encrypt
		if len(identityFlags) > 0 {
			log.Printf("Error: -i/--identity can't be used in encryption mode.")
			log.Fatalf("Did you forget to specify -d/--decrypt?")
		}
		if len(recipientFlags) == 0 && !passFlag {
			log.Printf("Error: missing recipients.")
			log.Fatalf("Did you forget to specify -r/--recipient or -p/--passphrase?")
		}
		if len(recipientFlags) > 0 && passFlag {
			log.Fatalf("Error: -p/--passphrase can't be combined with -r/--recipient.")
		}
	}

	var in, out io.ReadWriter = os.Stdin, os.Stdout
	if name := flag.Arg(0); name != "" && name != "-" {
		f, err := os.Open(name)
		if err != nil {
			log.Fatalf("Error: failed to open input file %q: %v", name, err)
		}
		defer f.Close()
		in = f
	} else {
		stdinInUse = true
	}
	if name := outFlag; name != "" && name != "-" {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
		if err != nil {
			log.Fatalf("Error: failed to open output file %q: %v", name, err)
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
			log.Printf("Error: refusing to output binary to the terminal.")
			log.Fatalf(`Did you mean to use -a/--armor? Force with "-o -".`)
		}
	}

	switch {
	case passFlag:
		fmt.Fprintf(os.Stderr, "Enter passphrase: ")
		pass, err := readPassphrase()
		if err != nil {
			log.Fatalf("Error: could not read passphrase: %v", err)
		}
		if decryptFlag {
			decryptPass(string(pass), in, out)
		} else {
			encryptPass(string(pass), in, out, armorFlag)
		}
	case decryptFlag:
		decryptKeys(identityFlags, in, out)
	default:
		encryptKeys(recipientFlags, in, out, armorFlag)
	}
}

func encryptKeys(keys []string, in io.Reader, out io.Writer, armor bool) {
	var recipients []age.Recipient
	for _, arg := range keys {
		r, err := parseRecipient(arg)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		recipients = append(recipients, r)
	}
	encrypt(recipients, in, out, armor)
}

func encryptPass(pass string, in io.Reader, out io.Writer, armor bool) {
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		log.Fatalf("Error: %v", err)
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
		log.Fatalf("Error: %v", err)
	}
	if _, err := io.Copy(w, in); err != nil {
		log.Fatalf("Error: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func decryptKeys(keys []string, in io.Reader, out io.Writer) {
	var identities []age.Identity
	// TODO: use the default location if no arguments are provided:
	// os.UserConfigDir()/age/keys.txt, ~/.ssh/id_rsa, ~/.ssh/id_ed25519
	for _, name := range keys {
		ids, err := parseIdentitiesFile(name)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		identities = append(identities, ids...)
	}
	decrypt(identities, in, out)
}

func decryptPass(pass string, in io.Reader, out io.Writer) {
	i, err := age.NewScryptIdentity(pass)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	decrypt([]age.Identity{i}, in, out)
}

func decrypt(identities []age.Identity, in io.Reader, out io.Writer) {
	r, err := age.Decrypt(in, identities...)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	if _, err := io.Copy(out, r); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
