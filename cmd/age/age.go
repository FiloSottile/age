// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"flag"
	"io"
	"log"
	"os"

	"github.com/FiloSottile/age/internal/age"
)

func main() {
	log.SetFlags(0)

	decryptFlag := flag.Bool("d", false, "decrypt the input")
	outFlag := flag.String("o", "", "output to `FILE` (default stdout)")
	inFlag := flag.String("i", "", "read from `FILE` (default stdin)")
	armorFlag := flag.Bool("a", false, "generate an armored file")
	flag.Parse()

	switch {
	case *decryptFlag:
		if *armorFlag {
			log.Fatalf("Invalid flag combination")
		}
	default: // encrypt
	}

	in, out := os.Stdin, os.Stdout
	if name := *inFlag; name != "" {
		f, err := os.Open(name)
		if err != nil {
			log.Fatalf("Failed to open input file %q: %v", name, err)
		}
		defer f.Close()
		in = f
	}
	if name := *outFlag; name != "" {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
		if err != nil {
			log.Fatalf("Failed to open output file %q: %v", name, err)
		}
		defer f.Close()
		out = f
	}

	switch {
	case *decryptFlag:
		decrypt(in, out)
	default:
		encrypt(in, out, *armorFlag)
	}
}

func encrypt(in io.Reader, out io.Writer, armor bool) {
	var recipients []age.Recipient
	for _, arg := range flag.Args() {
		r, err := parseRecipient(arg)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		recipients = append(recipients, r)
	}
	if len(recipients) == 0 {
		log.Fatalf("Missing recipients!")
	}

	ageEncrypt := age.Encrypt
	if armor {
		ageEncrypt = age.EncryptWithArmor
	}
	w, err := ageEncrypt(out, recipients...)
	if err != nil {
		log.Fatalf("Error initializing encryption: %v", err)
	}
	if _, err := io.Copy(w, in); err != nil {
		log.Fatalf("Error encrypting the input: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Error finalizing encryption: %v", err)
	}
}

func decrypt(in io.Reader, out io.Writer) {
	var identities []age.Identity
	// TODO: use the default location if no arguments are provided:
	// os.UserConfigDir()/age/keys.txt, ~/.ssh/id_rsa, ~/.ssh/id_ed25519
	for _, name := range flag.Args() {
		ids, err := parseIdentitiesFile(name)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		identities = append(identities, ids...)
	}

	r, err := age.Decrypt(in, identities...)
	if err != nil {
		log.Fatalf("Error initializing decryption: %v", err)
	}
	if _, err := io.Copy(out, r); err != nil {
		log.Fatalf("Error decrypting the input: %v", err)
	}
}
