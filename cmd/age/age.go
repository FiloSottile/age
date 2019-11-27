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
		outFlag                       string
		decryptFlag, armorFlag        bool
		recipientFlags, identityFlags multiFlag
	)

	flag.BoolVar(&decryptFlag, "d", false, "decrypt the input")
	flag.BoolVar(&decryptFlag, "decrypt", false, "decrypt the input")
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
		if len(recipientFlags) == 0 {
			log.Printf("Error: missing recipients.")
			log.Fatalf("Did you forget to specify -r/--recipient?")
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
	}
	if name := outFlag; name != "" && name != "-" {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
		if err != nil {
			log.Fatalf("Error: failed to open output file %q: %v", name, err)
		}
		defer f.Close()
		out = f
	} else if terminal.IsTerminal(int(os.Stdout.Fd())) {
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
	case decryptFlag:
		decrypt(identityFlags, in, out)
	default:
		encrypt(recipientFlags, in, out, armorFlag)
	}
}

func encrypt(args []string, in io.Reader, out io.Writer, armor bool) {
	var recipients []age.Recipient
	for _, arg := range args {
		r, err := parseRecipient(arg)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		recipients = append(recipients, r)
	}

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

func decrypt(args []string, in io.Reader, out io.Writer) {
	var identities []age.Identity
	// TODO: use the default location if no arguments are provided:
	// os.UserConfigDir()/age/keys.txt, ~/.ssh/id_rsa, ~/.ssh/id_ed25519
	for _, name := range args {
		ids, err := parseIdentitiesFile(name)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		identities = append(identities, ids...)
	}

	r, err := age.Decrypt(in, identities...)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	if _, err := io.Copy(out, r); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
