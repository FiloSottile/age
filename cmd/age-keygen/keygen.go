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
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	log.SetFlags(0)

	outFlag := flag.String("o", "", "output to `FILE` (default stdout)")
	qrFlag := flag.Bool("q", false, "generate QR Code from public key")
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

	if fi, err := out.Stat(); err == nil {
		if fi.Mode().IsRegular() && fi.Mode().Perm()&0004 != 0 {
			fmt.Fprintf(os.Stderr, "Warning: writing to a world-readable file.\n")
			fmt.Fprintf(os.Stderr, "Consider setting the umask to 066 and trying again.\n")
		}
	}

	generate(out, qrFlag)
}

func generate(out *os.File, qr *bool) {
	k, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatalf("Internal error: %v", err)
	}

	if !terminal.IsTerminal(int(out.Fd())) {
		fmt.Fprintf(os.Stderr, "Public key: %s\n", k.Recipient())
	}

	fmt.Fprintf(out, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(out, "# public key: %s\n", k.Recipient())

	if *qr {
		var q *qrcode.QRCode
		q, err = qrcode.New(k.Recipient().String(), qrcode.Low)

		if err != nil {
			log.Fatalf("Internal error: %v", err)
		}

		if !terminal.IsTerminal(int(out.Fd())) {
			fmt.Fprint(os.Stderr, "public key QR code:\n")
			fmt.Fprintf(os.Stderr, "%s\n", q.ToSmallString(false))
		} else {
			fmt.Fprint(out, "public key QR code:\n")
			fmt.Fprintf(out, "%s\n", q.ToSmallString(false))
		}
	}

	fmt.Fprintf(out, "%s\n", k)
}
