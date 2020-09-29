// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	log.SetFlags(0)

	outFlag := flag.String("o", "", "output to `FILE` (default stdout)")
	pubkeyFlag := flag.Bool("pubkey", false, "Read the private key file from standard input and print the corresponding public key.")
	flag.Parse()
	if len(flag.Args()) != 0 {
		log.Fatalf("age-keygen takes no arguments")
	}

	out := os.Stdout
	if name := *outFlag; name != "" {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			log.Fatalf("Failed to open output file %q: %v", name, err)
		}
		defer f.Close()
		out = f
	}

	if *pubkeyFlag {
		in := os.Stdin
		generatePubkey(out, in)
	} else {
		generatePrivkey(out)
	}
}

func generatePrivkey(out *os.File) {
	if fi, err := out.Stat(); err == nil {
		if fi.Mode().IsRegular() && fi.Mode().Perm()&0004 != 0 {
			fmt.Fprintf(os.Stderr, "Warning: writing to a world-readable file.\n"+
				"Consider setting the umask to 066 and trying again.\n")
		}
	}

	k, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatalf("Internal error: %v", err)
	}

	if !terminal.IsTerminal(int(out.Fd())) {
		fmt.Fprintf(os.Stderr, "Public key: %s\n", k.Recipient())
	}

	fmt.Fprintf(out, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(out, "# public key: %s\n", k.Recipient())
	fmt.Fprintf(out, "%s\n", k)
}

func generatePubkey(out *os.File, in *os.File) {
	ids, err := age.ParseIdentities(in)
	if err != nil {
		log.Fatalf("failed to read %q: %v", in.Name(), err)
	}
	if len(ids) == 0 {
		log.Fatalln("no identities found in input")
	} else if len(ids) > 1 {
		log.Fatalln("more than one identity provided in input")
	}
	id := ids[0]

	k, ok := id.(*age.X25519Identity)
	if !ok {
		log.Fatalf("identity is not an X25519 identity (but %q)", id.Type())
	}

	fmt.Fprintf(out, "%s\n", k.Recipient())
}
