// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"
	"time"

	"filippo.io/age"
	"golang.org/x/term"
)

const usage = `Usage:
    age-keygen [-o OUTPUT]
    age-keygen -y [-o OUTPUT] [INPUT]

Options:
    -o, --output OUTPUT       Write the result to the file at path OUTPUT.
    -y                        Convert an identity file to a recipients file.

age-keygen generates a new native X25519 key pair, and outputs it to
standard output or to the OUTPUT file.

If an OUTPUT file is specified, the public key is printed to standard error.
If OUTPUT already exists, it is not overwritten.

In -y mode, age-keygen reads an identity file from INPUT or from standard
input and writes the corresponding recipient(s) to OUTPUT or to standard
output, one per line, with no comments.

Examples:

    $ age-keygen
    # created: 2021-01-02T15:30:45+01:00
    # public key: age1lvyvwawkr0mcnnnncaghunadrqkmuf9e6507x9y920xxpp866cnql7dp2z
    AGE-SECRET-KEY-1N9JEPW6DWJ0ZQUDX63F5A03GX8QUW7PXDE39N8UYF82VZ9PC8UFS3M7XA9

    $ age-keygen -o key.txt
    Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

    $ age-keygen -y key.txt
    age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p`

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func main() {
	log.SetFlags(0)
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	var (
		versionFlag, convertFlag bool
		outFlag                  string
	)

	flag.BoolVar(&versionFlag, "version", false, "print the version")
	flag.BoolVar(&convertFlag, "y", false, "convert identities to recipients")
	flag.StringVar(&outFlag, "o", "", "output to `FILE` (default stdout)")
	flag.StringVar(&outFlag, "output", "", "output to `FILE` (default stdout)")
	flag.Parse()
	if len(flag.Args()) != 0 && !convertFlag {
		errorf("too many arguments")
	}
	if len(flag.Args()) > 1 && convertFlag {
		errorf("too many arguments")
	}
	if versionFlag {
		if Version != "" {
			fmt.Println(Version)
			return
		}
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			fmt.Println(buildInfo.Main.Version)
			return
		}
		fmt.Println("(unknown)")
		return
	}

	out := os.Stdout
	if outFlag != "" {
		f, err := os.OpenFile(outFlag, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			errorf("failed to open output file %q: %v", outFlag, err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				errorf("failed to close output file %q: %v", outFlag, err)
			}
		}()
		out = f
	}

	in := os.Stdin
	if inFile := flag.Arg(0); inFile != "" && inFile != "-" {
		f, err := os.Open(inFile)
		if err != nil {
			errorf("failed to open input file %q: %v", inFile, err)
		}
		defer f.Close()
		in = f
	}

	if convertFlag {
		convert(in, out)
	} else {
		if fi, err := out.Stat(); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0004 != 0 {
			warning("writing secret key to a world-readable file")
		}
		generate(out)
	}
}

func generate(out *os.File) {
	k, err := age.GenerateX25519Identity()
	if err != nil {
		errorf("internal error: %v", err)
	}

	if !term.IsTerminal(int(out.Fd())) {
		fmt.Fprintf(os.Stderr, "Public key: %s\n", k.Recipient())
	}

	fmt.Fprintf(out, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(out, "# public key: %s\n", k.Recipient())
	fmt.Fprintf(out, "%s\n", k)
}

func convert(in io.Reader, out io.Writer) {
	ids, err := age.ParseIdentities(in)
	if err != nil {
		errorf("failed to parse input: %v", err)
	}
	if len(ids) == 0 {
		errorf("no identities found in the input")
	}
	for _, id := range ids {
		id, ok := id.(*age.X25519Identity)
		if !ok {
			errorf("internal error: unexpected identity type: %T", id)
		}
		fmt.Fprintf(out, "%s\n", id.Recipient())
	}
}

func errorf(format string, v ...interface{}) {
	log.Printf("age-keygen: error: "+format, v...)
	log.Fatalf("age-keygen: report unexpected or unhelpful errors at https://filippo.io/age/report")
}

func warning(msg string) {
	log.Printf("age-keygen: warning: %s", msg)
}
