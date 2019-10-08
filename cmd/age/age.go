// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"crypto/rand"
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/FiloSottile/age/internal/age"
)

func main() {
	log.SetFlags(0)

	generateFlag := flag.Bool("generate", false, "generate a new age key pair")
	decryptFlag := flag.Bool("d", false, "decrypt the input")
	infileFlag := flag.String("i", "", "output file")
	outfileFlag := flag.String("o", "", "input file")
	flag.Parse()

	var (
		in, out *os.File
		err     error
	)

	if *generateFlag && *decryptFlag {
		log.Fatalf("Invalid flag combination")
	}

	if len(*infileFlag) > 0 {
		if *generateFlag {
			log.Fatalf("-generate takes no inputs")
		}

		in, err = os.Open(*infileFlag)
		if err != nil {
			log.Fatalf("cannot open file %s: %v", *infileFlag, err)
		}
	} else {
		in = os.Stdin
	}

	if len(*outfileFlag) > 0 {
		out, err = os.Create(*outfileFlag)
		if err != nil {
			log.Fatalf("cannot open file %s: %v", *outfileFlag, err)
		}
	} else {
		out = os.Stdout
	}

	switch {
	case *generateFlag:
		generate(out)
	case *decryptFlag:
		decrypt(in, out)
	default:
		encrypt(in, out)
	}
}

func generate(out *os.File) {
	if len(flag.Args()) != 0 {
		log.Fatalf("-generate takes no arguments")
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Internal error: %v", err)
	}
	k, err := age.NewX25519Identity(key)
	if err != nil {
		log.Fatalf("Internal error: %v", err)
	}

	out.WriteString("# created: " + time.Now().Format(time.RFC3339) + "\n")
	out.WriteString("# " + k.Recipient().String() + "\n")
	out.WriteString(k.String() + "\n")
}

func encrypt(in, out *os.File) {
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

	w, err := age.Encrypt(out, recipients...)
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

func decrypt(in, out *os.File) {
	var identities []age.Identity
	// TODO: use the default location if no arguments are provided.
	for _, name := range flag.Args() {
		var (
			ids []age.Identity
			err error
		)

		// TODO: smarter detection logic than looking for .ssh/* in the path.
		if filepath.Base(filepath.Dir(name)) == ".ssh" {
			ids, err = parseSSHIdentity(name)
		} else {
			ids, err = parseIdentitiesFile(name)
		}
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
