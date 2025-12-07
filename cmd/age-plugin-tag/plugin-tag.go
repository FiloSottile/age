package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
)

const usage = `age-plugin-tag is an age plugin for P-256 tagged recipients. These are supported
natively by age v1.3.0 and later, but this plugin can be placed in $PATH to add
support to any version and implementation of age that supports plugins.

Usually, tagged recipients are the public side of private keys held in hardware,
where the identity side is handled by a different plugin.`

func main() {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	p, err := plugin.New("tag")
	if err != nil {
		log.Fatal(err)
	}
	p.HandleRecipient(func(b []byte) (age.Recipient, error) {
		return tag.NewClassicRecipient(b)
	})
	os.Exit(p.Main())
}
