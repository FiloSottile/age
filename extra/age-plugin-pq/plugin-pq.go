package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"

	"filippo.io/age"
	"filippo.io/age/internal/bech32"
	"filippo.io/age/plugin"
)

const usage = `Usage:
    age-plugin-pq -identity [-o OUTPUT] [INPUT]

Options:
    -identity                 Convert one or more native post-quantum identities from
                              INPUT or from standard input to plugin identities.
    -o, --output OUTPUT       Write the result to the file at path OUTPUT instead of
                              standard output.

age-plugin-pq is an age plugin for post-quantum hybrid ML-KEM-768 + X25519
recipients and identities. These are supported natively by age v1.3.0 and later,
but this plugin can be placed in $PATH to add support to any version and
implementation of age that supports plugins.

Recipients work out of the box, while identities need to be converted to plugin
identities with -identity. If OUTPUT already exists, it is not overwritten.`

// Version can be set at link time to override debug.BuildInfo.Main.Version when
// building manually without git history. It should look like "v1.2.3".
var Version string

func main() {
	log.SetFlags(0)

	p, err := plugin.New("pq")
	if err != nil {
		errorf("failed to create plugin: %v", err)
	}
	p.RegisterFlags(nil)

	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	var outFlag string
	var versionFlag, identityFlag bool
	flag.BoolVar(&versionFlag, "version", false, "print the version")
	flag.BoolVar(&identityFlag, "identity", false, "convert identities to plugin identities")
	flag.StringVar(&outFlag, "o", "", "output to `FILE` (default stdout)")
	flag.StringVar(&outFlag, "output", "", "output to `FILE` (default stdout)")
	flag.Parse()

	if versionFlag {
		if buildInfo, ok := debug.ReadBuildInfo(); ok && Version == "" {
			Version = buildInfo.Main.Version
		}
		fmt.Println(Version)
		return
	}

	if identityFlag {
		if len(flag.Args()) > 1 {
			errorf("too many arguments")
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
		if fi, err := out.Stat(); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0004 != 0 {
			warning("writing secret key to a world-readable file")
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

		convert(in, out)
		return
	}

	p.HandleRecipientEncoding(func(s string) (age.Recipient, error) {
		return age.ParseHybridRecipient(s)
	})
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		// Convert from a AGE-PLUGIN-PQ-1... payload to a
		// AGE-SECRET-KEY-PQ-1... identity encoding.
		s, err := bech32.Encode("AGE-SECRET-KEY-PQ-", data)
		if err != nil {
			return nil, err
		}
		return age.ParseHybridIdentity(s)
	})
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		s, err := bech32.Encode("AGE-SECRET-KEY-PQ-", data)
		if err != nil {
			return nil, err
		}
		i, err := age.ParseHybridIdentity(s)
		if err != nil {
			return nil, err
		}
		return i.Recipient(), nil
	})
	os.Exit(p.Main())
}

func convert(in io.Reader, out io.Writer) {
	ids, err := age.ParseIdentities(in)
	if err != nil {
		errorf("failed to parse identities: %v", err)
	}
	for i, id := range ids {
		hybridID, ok := id.(*age.HybridIdentity)
		if !ok {
			errorf("identity #%d is not a post-quantum hybrid identity", i+1)
		}
		_, data, err := bech32.Decode(hybridID.String())
		if err != nil {
			errorf("failed to decode identity #%d: %v", i+1, err)
		}
		fmt.Fprintln(out, plugin.EncodeIdentity("pq", data))
	}
}

func errorf(format string, v ...any) {
	log.Printf("age-plugin-pq: error: "+format, v...)
	log.Fatalf("age-plugin-pq: report unexpected or unhelpful errors at https://filippo.io/age/report")
}

func warning(msg string) {
	log.Printf("age-plugin-pq: warning: %s", msg)
}
