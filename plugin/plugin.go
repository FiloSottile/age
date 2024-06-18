package plugin

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"filippo.io/age"
	"filippo.io/age/internal/format"
)

type Plugin struct {
	name string
	fs   *flag.FlagSet
	sm   *string

	recipient     func([]byte) (age.Recipient, error)
	idAsRecipient func([]byte) (age.Recipient, error)
	identity      func([]byte) (age.Identity, error)
}

func New(name string) (*Plugin, error) {
	return &Plugin{name: name}, nil
}

func (p *Plugin) Name() string {
	return p.name
}

func (p *Plugin) RegisterFlags(fs *flag.FlagSet) {
	if fs == nil {
		fs = flag.CommandLine
	}
	p.fs = fs
	p.sm = fs.String("age-plugin", "", "age-plugin state machine")
}

func (p *Plugin) HandleRecipient(f func(data []byte) (age.Recipient, error)) {
	if p.recipient != nil {
		panic("HandleRecipient called twice")
	}
	p.recipient = f
}

func (p *Plugin) HandleIdentityAsRecipient(f func(data []byte) (age.Recipient, error)) {
	if p.idAsRecipient != nil {
		panic("HandleIdentityAsRecipient called twice")
	}
	p.idAsRecipient = f
}

func (p *Plugin) HandleIdentity(f func(data []byte) (age.Identity, error)) {
	if p.identity != nil {
		panic("HandleIdentity called twice")
	}
	p.identity = f
}

func (p *Plugin) Main() int {
	if p.fs == nil {
		p.RegisterFlags(nil)
	}
	if !p.fs.Parsed() {
		p.fs.Parse(os.Args[1:])
	}
	if *p.sm == "recipient-v1" {
		return p.RecipientV1()
	}
	if *p.sm == "identity-v1" {
		return p.IdentityV1()
	}
	return fatalf("unknown state machine %q", *p.sm)
}

func (p *Plugin) RecipientV1() int {
	if p.recipient == nil && p.idAsRecipient == nil {
		return fatalf("recipient-v1 not supported")
	}

	var recipientStrings, identityStrings []string
	var fileKeys [][]byte
	var supportsLabels bool

	sr := format.NewStanzaReader(bufio.NewReader(os.Stdin))
ReadLoop:
	for {
		s, err := sr.ReadStanza()
		if err != nil {
			return fatalf("failed to read stanza: %v", err)
		}

		switch s.Type {
		case "add-recipient":
			if err := expectStanzaWithNoBody(s, 1); err != nil {
				return fatalf("%v", err)
			}
			recipientStrings = append(recipientStrings, s.Args[0])
		case "add-identity":
			if err := expectStanzaWithNoBody(s, 1); err != nil {
				return fatalf("%v", err)
			}
			identityStrings = append(identityStrings, s.Args[0])
		case "extension-labels":
			if err := expectStanzaWithNoBody(s, 0); err != nil {
				return fatalf("%v", err)
			}
			supportsLabels = true
		case "wrap-file-key":
			if err := expectStanzaWithBody(s, 0); err != nil {
				return fatalf("%v", err)
			}
			fileKeys = append(fileKeys, s.Body)
		case "done":
			if err := expectStanzaWithNoBody(s, 0); err != nil {
				return fatalf("%v", err)
			}
			break ReadLoop
		default:
			// Unsupported stanzas in uni-directional phases are ignored.
		}
	}

	if len(recipientStrings)+len(identityStrings) == 0 {
		return fatalf("no recipients or identities provided")
	}
	if len(fileKeys) == 0 {
		return fatalf("no file keys provided")
	}

	var recipients, identities []age.Recipient
	for i, s := range recipientStrings {
		name, data, err := ParseRecipient(s)
		if err != nil {
			return recipientError(sr, i, err)
		}
		if name != p.name {
			return recipientError(sr, i, fmt.Errorf("unsupported plugin name: %q", name))
		}
		if p.recipient == nil {
			return recipientError(sr, i, fmt.Errorf("recipient encodings not supported"))
		}
		r, err := p.recipient(data)
		if err != nil {
			return recipientError(sr, i, err)
		}
		recipients = append(recipients, r)
	}
	for i, s := range identityStrings {
		name, data, err := ParseIdentity(s)
		if err != nil {
			return identityError(sr, i, err)
		}
		if name != p.name {
			return identityError(sr, i, fmt.Errorf("unsupported plugin name: %q", name))
		}
		if p.idAsRecipient == nil {
			return identityError(sr, i, fmt.Errorf("identity encodings not supported"))
		}
		r, err := p.idAsRecipient(data)
		if err != nil {
			return identityError(sr, i, err)
		}
		identities = append(identities, r)
	}

	// Technically labels should be per-file key, but the client-side protocol
	// extension shipped like this, and it doesn't feel worth making a v2.
	var labels []string

	stanzas := make([][]*age.Stanza, len(fileKeys))
	for i, fk := range fileKeys {
		for j, r := range recipients {
			ss, ll, err := wrapWithLabels(r, fk)
			if err != nil {
				return recipientError(sr, j, err)
			}
			if i == 0 && j == 0 {
				labels = ll
			} else if err := checkLabels(ll, labels); err != nil {
				return recipientError(sr, j, err)
			}
			stanzas[i] = append(stanzas[i], ss...)
		}
		for j, r := range identities {
			ss, ll, err := wrapWithLabels(r, fk)
			if err != nil {
				return identityError(sr, j, err)
			}
			if i == 0 && j == 0 && len(recipients) == 0 {
				labels = ll
			} else if err := checkLabels(ll, labels); err != nil {
				return identityError(sr, j, err)
			}
			stanzas[i] = append(stanzas[i], ss...)
		}
	}

	if supportsLabels {
		if err := writeStanza(os.Stdout, "labels", labels...); err != nil {
			return fatalf("failed to write labels stanza: %v", err)
		}
		if err := expectOk(sr); err != nil {
			return fatalf("%v", err)
		}
	}

	for i, ss := range stanzas {
		for _, s := range ss {
			if err := (&format.Stanza{Type: "recipient-stanza",
				Args: append([]string{fmt.Sprint(i), s.Type}, s.Args...),
				Body: s.Body}).Marshal(os.Stdout); err != nil {
				return fatalf("failed to write recipient-stanza: %v", err)
			}
			if err := expectOk(sr); err != nil {
				return fatalf("%v", err)
			}
		}
	}

	if err := writeStanza(os.Stdout, "done"); err != nil {
		return fatalf("failed to write done stanza: %v", err)
	}
	return 0
}

func wrapWithLabels(r age.Recipient, fileKey []byte) ([]*age.Stanza, []string, error) {
	if r, ok := r.(age.RecipientWithLabels); ok {
		return r.WrapWithLabels(fileKey)
	}
	s, err := r.Wrap(fileKey)
	return s, nil, err
}

func checkLabels(ll, labels []string) error {
	if !slicesEqual(ll, labels) {
		return fmt.Errorf("labels %q do not match previous recipients %q", ll, labels)
	}
	return nil
}

func (p *Plugin) IdentityV1() int {
	if p.identity == nil {
		return fatalf("identity-v1 not supported")
	}

	var files [][]*age.Stanza
	var identityStrings []string

	sr := format.NewStanzaReader(bufio.NewReader(os.Stdin))
ReadLoop:
	for {
		s, err := sr.ReadStanza()
		if err != nil {
			return fatalf("failed to read stanza: %v", err)
		}

		switch s.Type {
		case "add-identity":
			if err := expectStanzaWithNoBody(s, 1); err != nil {
				return fatalf("%v", err)
			}
			identityStrings = append(identityStrings, s.Args[0])
		case "recipient-stanza":
			if len(s.Args) < 2 {
				return fatalf("recipient-stanza stanza has %d arguments, want >=2", len(s.Args))
			}
			i, err := strconv.Atoi(s.Args[0])
			if err != nil {
				return fatalf("failed to parse recipient-stanza stanza argument: %v", err)
			}
			ss := &age.Stanza{Type: s.Args[1], Args: s.Args[2:], Body: s.Body}
			switch i {
			case len(files):
				files = append(files, []*age.Stanza{ss})
			case len(files) - 1:
				files[len(files)-1] = append(files[len(files)-1], ss)
			default:
				return fatalf("unexpected file index %d, previous was %d", i, len(files)-1)
			}
		case "done":
			if err := expectStanzaWithNoBody(s, 0); err != nil {
				return fatalf("%v", err)
			}
			break ReadLoop
		default:
			// Unsupported stanzas in uni-directional phases are ignored.
		}
	}

	if len(identityStrings) == 0 {
		return fatalf("no identities provided")
	}
	if len(files) == 0 {
		return fatalf("no stanzas provided")
	}

	var identities []age.Identity
	for i, s := range identityStrings {
		name, data, err := ParseIdentity(s)
		if err != nil {
			return identityError(sr, i, err)
		}
		if name != p.name {
			return identityError(sr, i, fmt.Errorf("unsupported plugin name: %q", name))
		}
		if p.identity == nil {
			return identityError(sr, i, fmt.Errorf("identity encodings not supported"))
		}
		r, err := p.identity(data)
		if err != nil {
			return identityError(sr, i, err)
		}
		identities = append(identities, r)
	}

	for i, ss := range files {
		// TODO: there should be a mechanism to let the plugin decide the order
		// in which identities are tried.
		for _, id := range identities {
			fk, err := id.Unwrap(ss)
			if errors.Is(err, age.ErrIncorrectIdentity) {
				continue
			} else if err != nil {
				if err := writeError(sr, []string{"stanza", fmt.Sprint(i), "0"}, err); err != nil {
					return fatalf("%v", err)
				}
				// Note that we don't exit here, as the protocol allows
				// continuing with other files.
				break
			}

			s := &format.Stanza{Type: "file-key", Args: []string{fmt.Sprint(i)}, Body: fk}
			if err := s.Marshal(os.Stdout); err != nil {
				return fatalf("failed to write file-key: %v", err)
			}
			if err := expectOk(sr); err != nil {
				return fatalf("%v", err)
			}
			break
		}
	}

	if err := writeStanza(os.Stdout, "done"); err != nil {
		return fatalf("failed to write done stanza: %v", err)
	}
	return 0
}

func expectStanzaWithNoBody(s *format.Stanza, wantArgs int) error {
	if len(s.Args) != wantArgs {
		return fmt.Errorf("%s stanza has %d arguments, want %d", s.Type, len(s.Args), wantArgs)
	}
	if len(s.Body) != 0 {
		return fmt.Errorf("%s stanza has %d bytes of body, want 0", s.Type, len(s.Body))
	}
	return nil
}

func expectStanzaWithBody(s *format.Stanza, wantArgs int) error {
	if len(s.Args) != wantArgs {
		return fmt.Errorf("%s stanza has %d arguments, want %d", s.Type, len(s.Args), wantArgs)
	}
	if len(s.Body) == 0 {
		return fmt.Errorf("%s stanza has 0 bytes of body, want >0", s.Type)
	}
	return nil
}

func recipientError(sr *format.StanzaReader, idx int, err error) int {
	if err := writeError(sr, []string{"recipient", fmt.Sprint(idx)}, err); err != nil {
		return fatalf("%v", err)
	}
	return 3
}

func identityError(sr *format.StanzaReader, idx int, err error) int {
	if err := writeError(sr, []string{"identity", fmt.Sprint(idx)}, err); err != nil {
		return fatalf("%v", err)
	}
	return 3
}

func expectOk(sr *format.StanzaReader) error {
	ok, err := sr.ReadStanza()
	if err != nil {
		return fmt.Errorf("failed to read OK stanza: %v", err)
	}
	if ok.Type != "ok" {
		return fmt.Errorf("expected OK stanza, got %q", ok.Type)
	}
	return expectStanzaWithNoBody(ok, 0)
}

func writeError(sr *format.StanzaReader, args []string, err error) error {
	s := &format.Stanza{Type: "error", Args: args}
	s.Body = []byte(err.Error())
	if err := s.Marshal(os.Stdout); err != nil {
		return fmt.Errorf("failed to write error stanza: %v", err)
	}
	if err := expectOk(sr); err != nil {
		return fmt.Errorf("%v", err)
	}
	return nil
}

func fatalf(format string, args ...interface{}) int {
	fmt.Fprintf(os.Stderr, format, args...)
	return 1
}

func slicesEqual(s1, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}
