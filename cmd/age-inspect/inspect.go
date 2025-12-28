// Copyright 2025 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"filippo.io/age/internal/inspect"
)

const usage = `Usage:
    age-inspect [--json] [INPUT]

Options:
    --json                      Output machine-readable JSON.

INPUT defaults to standard input. "-" may be used as INPUT to explicitly
read from standard input.`

// Version can be set at link time to override debug.BuildInfo.Main.Version when
// building manually without git history. It should look like "v1.2.3".
var Version string

func main() {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	var (
		versionFlag bool
		jsonFlag    bool
	)

	flag.BoolVar(&versionFlag, "version", false, "print the version")
	flag.BoolVar(&jsonFlag, "json", false, "output machine-readable JSON")
	flag.Parse()

	if versionFlag {
		if buildInfo, ok := debug.ReadBuildInfo(); ok && Version == "" {
			Version = buildInfo.Main.Version
		}
		fmt.Println(Version)
		return
	}

	if flag.NArg() > 1 {
		flag.Usage()
		os.Exit(1)
	}

	in := os.Stdin
	var fileSize int64 = -1
	if name := flag.Arg(0); name != "" && name != "-" {
		f, err := os.Open(name)
		if err != nil {
			errorf("failed to open input file %q: %v", name, err)
		}
		defer f.Close()
		in = f
		if stat, err := f.Stat(); err == nil && stat.Mode().IsRegular() {
			fileSize = stat.Size()
		}
	}

	data, err := inspect.Inspect(in, fileSize)
	if err != nil {
		errorf("inspection failed: %v", err)
	}

	if jsonFlag {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "    ")
		if err := enc.Encode(data); err != nil {
			errorf("failed to encode JSON output: %v", err)
		}
	} else {
		name := flag.Arg(0)
		if name == "" {
			name = "<stdin>"
		}
		fmt.Printf("%s is an age file, version %q.\n", name, data.Version)
		fmt.Printf("\n")
		if data.Armor {
			fmt.Printf("This file is ASCII-armored.\n")
			fmt.Printf("\n")
		}
		fmt.Printf("This file is encrypted to the following recipient types:\n")
		for _, t := range data.StanzaTypes {
			fmt.Printf("  - %q\n", t)
		}
		fmt.Printf("\n")
		switch data.Postquantum {
		case "yes":
			fmt.Printf("This file uses post-quantum encryption.\n")
			fmt.Printf("\n")
		case "no":
			fmt.Printf("This file does NOT use post-quantum encryption.\n")
			fmt.Printf("\n")
		}
		fmt.Printf("Size breakdown (assuming it decrypts successfully):\n")
		fmt.Printf("\n")
		fmt.Printf("    Header              % 12d bytes\n", data.Sizes.Header)
		if data.Armor {
			fmt.Printf("    Armor overhead      % 12d bytes\n", data.Sizes.Armor)
		}
		fmt.Printf("    Encryption overhead % 12d bytes\n", data.Sizes.Overhead)
		fmt.Printf("    Payload             % 12d bytes\n", data.Sizes.MinPayload)
		fmt.Printf("                        -------------------\n")
		total := data.Sizes.Header + data.Sizes.Overhead + data.Sizes.MinPayload + data.Sizes.Armor
		fmt.Printf("    Total               % 12d bytes\n", total)
		fmt.Printf("\n")
		fmt.Printf("Tip: for machine-readable output, use --json.\n")
	}
}

// l is a logger with no prefixes.
var l = log.New(os.Stderr, "", 0)

func errorf(format string, v ...any) {
	l.Printf("age-inspect: error: "+format, v...)
	l.Printf("age-inspect: report unexpected or unhelpful errors at https://filippo.io/age/report")
	os.Exit(1)
}
