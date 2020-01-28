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

	"filippo.io/age/internal/age"
	"golang.org/x/crypto/ssh/terminal"
)

var version = "not compiled with version information"
var commit string

const usage = `Usage:
    age-keygen [>> /path/to/keyfile]
    age-keygen -o OUTPUT

Options:
    -o OUTPUT         Write the result to the file at path OUTPUT.
    -v, --version     Print the version string and exit
    -h, --help        Print this message and exit

If -o is not provided, OUTPUT defaults to standard output

Example:
    $ age-keygen -o key.txt
    Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p`

func main() {
	log.SetFlags(0)
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	var verFlag, helpFlag bool
	flag.BoolVar(&verFlag, "v", false, "print version and quit")
	flag.BoolVar(&verFlag, "version", false, "print version and quit")
	flag.BoolVar(&helpFlag, "h", false, "print usage and quit")
	flag.BoolVar(&helpFlag, "help", false, "print usage and quit")
	outFlag := flag.String("o", "", "output to `FILE` (default stdout)")
	flag.Parse()
	switch {
	case helpFlag:
		fmt.Printf("%s\n", usage)
		os.Exit(0)
	case verFlag:
		if commit != "" {
			fmt.Printf("Version: %s\nHash: %s\n", version, commit)
		} else {
			fmt.Printf("Version: %s\n", version)
		}
		os.Exit(0)
	}
	if len(flag.Args()) != 0 {
		log.Fatalf("age-keygen takes no arguments.\n"+
			"Run age-keygen -h for help")
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

	if fi, err := out.Stat(); err == nil {
		if fi.Mode().IsRegular() && fi.Mode().Perm()&0004 != 0 {
			fmt.Fprintf(os.Stderr, "Warning: writing to a world-readable file.\n")
			fmt.Fprintf(os.Stderr, "Consider setting the umask to 066 and trying again.\n")
		}
	}

	generate(out)
}

func generate(out *os.File) {
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
