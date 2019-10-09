// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"crypto/rand"
	"flag"
	"fmt"
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
	flag.Parse()

	switch {
	case *generateFlag && *decryptFlag:
		log.Fatalf("Invalid flag combination")
	case *generateFlag:
		generate()
	case *decryptFlag:
		decrypt()
	default:
		encrypt()
	}
}

func generate() {
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

	fmt.Printf("# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("# %s\n", k.Recipient())
	fmt.Printf("%s\n", k)
}

func encrypt() {
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

	w, err := age.Encrypt(os.Stdout, recipients...)
	if err != nil {
		log.Fatalf("Error initializing encryption: %v", err)
	}
	if _, err := io.Copy(w, os.Stdin); err != nil {
		log.Fatalf("Error encrypting the input: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Error finalizing encryption: %v", err)
	}
}

func decrypt() {
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

	r, err := age.Decrypt(os.Stdin, identities...)
	if err != nil {
		log.Fatalf("Error initializing decryption: %v", err)
	}
	if _, err := io.Copy(os.Stdout, r); err != nil {
		log.Fatalf("Error decrypting the input: %v", err)
	}
}
