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
	"runtime/debug"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh/terminal"
)

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func main() {
	log.SetFlags(0)

	outFlag := flag.String("o", "", "output to `FILE` (default stdout)")
	versionFlag := flag.Bool("version", false, "print the version")
	flag.Parse()
	if len(flag.Args()) != 0 {
		log.Fatalf("age-keygen takes no arguments")
	}
	if *versionFlag {
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
			fmt.Fprintf(os.Stderr, "Warning: writing to a world-readable file.\n"+
				"Consider setting the umask to 066 and trying again.\n")
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
