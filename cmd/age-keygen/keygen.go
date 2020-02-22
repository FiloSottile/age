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
	"os/user"
	"time"

	"filippo.io/age/internal/age"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	log.SetFlags(0)

	outFlag := flag.String("o", "", "output to ~/.age/`FILE`.pub and ~/.age/FILE.key (default \"me\")")
	flag.Parse()
	if len(flag.Args()) != 0 {
		log.Fatalf("age-keygen takes no arguments")
	}

	// create ~/.age if it doesn't exist
	usr, _ := user.Current()
	agedir := usr.HomeDir + "/.age/"
	if _, err := os.Stat(agedir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "%s does not exist, creating\n", agedir)
		err := os.Mkdir(agedir, 0700)
		if err != nil {
			log.Fatalf("Unable to make .age directory in %s, exiting\n", usr.HomeDir)
		}
	}

	fpname := "me.pub"
	fkname := "me.key"
	if name := *outFlag; name != "" {
		fpname = name + ".pub"
		fkname = name + ".key"
	}
	fpfullname := agedir + fpname
	fkfullname := agedir + fkname
	fp, err := os.OpenFile(fpfullname, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Fatalf("Failed to open pub output file %s: %v", fpname, err)
	}
	defer fp.Close()
	fk, err := os.OpenFile(fkfullname, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Fatalf("Failed to open key output file %s: %v", fkname, err)
	}
	defer fk.Close()

	if fi, err := key.Stat(); err == nil {
		if fi.Mode().IsRegular() && fi.Mode().Perm()&0004 != 0 {
			fmt.Fprintf(os.Stderr, "Warning: writing key to a world-readable file.\n")
			fmt.Fprintf(os.Stderr, "Consider setting the umask to 066 and trying again.\n")
		}
	}

	generate(fp, fk)

	if terminal.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintf(os.Stderr, "%s and %s written\n", fpfullname, fkfullname)
	}
}

func generate(pub *os.File, key *os.File) {
	k, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatalf("Internal error: %v", err)
	}

	fmt.Fprintf(pub, "%s\n", k.Recipient())
	fmt.Fprintf(key, "%s\n", k)

	if terminal.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprintf(os.Stderr, "Public key: %s\n", k.Recipient())
	  fmt.Fprintf(os.Stderr, "Created at: %s\n", time.Now().Format(time.RFC3339))
	}
}
