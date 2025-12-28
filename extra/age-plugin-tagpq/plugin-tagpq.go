package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
)

const usage = `age-plugin-tagpq is an age plugin for ML-KEM-768 + P-256 post-quantum hybrid
tagged recipients. These are supported natively by age v1.3.0 and later, but
this plugin can be placed in $PATH to add support to any version and
implementation of age that supports plugins.

Usually, tagged recipients are the public side of private keys held in hardware,
where the identity side is handled by a different plugin.`

// Version can be set at link time to override debug.BuildInfo.Main.Version when
// building manually without git history. It should look like "v1.2.3".
var Version string

func main() {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	p, err := plugin.New("tagpq")
	if err != nil {
		log.Fatal(err)
	}
	p.RegisterFlags(nil)

	versionFlag := flag.Bool("version", false, "print the version")
	flag.Parse()

	if *versionFlag {
		if buildInfo, ok := debug.ReadBuildInfo(); ok && Version == "" {
			Version = buildInfo.Main.Version
		}
		fmt.Println(Version)
		return
	}

	p.HandleRecipient(func(b []byte) (age.Recipient, error) {
		return tag.NewHybridRecipient(b)
	})

	os.Exit(p.Main())
}
