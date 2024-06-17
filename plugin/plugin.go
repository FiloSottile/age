package plugin

import (
	"bufio"
	"flag"
	"fmt"
	"os"

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

func (p *Plugin) Main() {
	if p.fs == nil {
		p.RegisterFlags(nil)
	}
	if !p.fs.Parsed() {
		p.fs.Parse(os.Args[1:])
	}
	if *p.sm == "recipient-v1" {
		p.RecipientV1()
	}
	if *p.sm == "identity-v1" {
		p.IdentityV1()
	}
}

func (p *Plugin) RecipientV1() {
	if p.recipient == nil {
		fatalf("recipient-v1 not supported")
	}

	var recipientStrings, identityStrings []string
	var fileKeys [][]byte
	var supportsLabels bool

	sr := format.NewStanzaReader(bufio.NewReader(os.Stdin))
ReadLoop:
	for {
		s, err := sr.ReadStanza()
		if err != nil {
			fatalf("failed to read stanza: %v", err)
		}

		switch s.Type {
		case "add-recipient":
			expectStanzaWithNoBody(s, 1)
			recipientStrings = append(recipientStrings, s.Args[0])
		case "add-identity":
			expectStanzaWithNoBody(s, 1)
			identityStrings = append(identityStrings, s.Args[0])
		case "extension-labels":
			expectStanzaWithNoBody(s, 0)
			supportsLabels = true
		case "wrap-file-key":
			expectStanzaWithBody(s, 0)
			fileKeys = append(fileKeys, s.Body)
		case "done":
			expectStanzaWithNoBody(s, 0)
			break ReadLoop
		default:
			// Unsupported stanzas in uni-directional phases are ignored.
		}
	}

	if len(recipientStrings)+len(identityStrings) == 0 {
		fatalf("no recipients or identities provided")
	}
	if len(fileKeys) == 0 {
		fatalf("no file keys provided")
	}

	var recipients, identities []age.Recipient
	for i, s := range recipientStrings {
		name, data, err := ParseRecipient(s)
		if err != nil {
			recipientError(sr, i, err)
		}
		if name != p.name {
			recipientError(sr, i, fmt.Errorf("unsupported plugin name: %q", name))
		}
		r, err := p.recipient(data)
		if err != nil {
			recipientError(sr, i, err)
		}
		recipients = append(recipients, r)
	}
	for i, s := range identityStrings {
		name, data, err := ParseIdentity(s)
		if err != nil {
			identityError(sr, i, err)
		}
		if name != p.name {
			identityError(sr, i, fmt.Errorf("unsupported plugin name: %q", name))
		}
		r, err := p.idAsRecipient(data)
		if err != nil {
			identityError(sr, i, err)
		}
		identities = append(identities, r)
	}

	stanzas := make([][]*age.Stanza, len(fileKeys))
	for i, fk := range fileKeys {
		for j, r := range recipients {
			ss, err := r.Wrap(fk)
			if err != nil {
				recipientError(sr, j, err)
			}
			stanzas[i] = append(stanzas[i], ss...)
		}
		for j, r := range identities {
			ss, err := r.Wrap(fk)
			if err != nil {
				identityError(sr, j, err)
			}
			stanzas[i] = append(stanzas[i], ss...)
		}
	}
	_ = supportsLabels // TODO

	for i, ss := range stanzas {
		for _, s := range ss {
			if err := (&format.Stanza{Type: "recipient-stanza",
				Args: append([]string{fmt.Sprint(i), s.Type}, s.Args...),
				Body: s.Body}).Marshal(os.Stdout); err != nil {
				fatalf("failed to write recipient-stanza: %v", err)
			}
			expectOk(sr)
		}
	}

	if err := writeStanza(os.Stdout, "done"); err != nil {
		fatalf("failed to write done stanza: %v", err)
	}
}

func (p *Plugin) IdentityV1() {
	if p.identity == nil {
		fatalf("identity-v1 not supported")
	}
	panic("not implemented")
}

func expectStanzaWithNoBody(s *format.Stanza, wantArgs int) {
	if len(s.Args) != wantArgs {
		fatalf("%s stanza has %d arguments, want %d", s.Type, len(s.Args), wantArgs)
	}
	if len(s.Body) != 0 {
		fatalf("%s stanza has %d bytes of body, want 0", s.Type, len(s.Body))
	}
}

func expectStanzaWithBody(s *format.Stanza, wantArgs int) {
	if len(s.Args) != wantArgs {
		fatalf("%s stanza has %d arguments, want %d", s.Type, len(s.Args), wantArgs)
	}
	if len(s.Body) == 0 {
		fatalf("%s stanza has 0 bytes of body, want >0", s.Type)
	}
}

func recipientError(sr *format.StanzaReader, idx int, err error) {
	protocolError(sr, []string{"recipient", fmt.Sprint(idx)}, err)
}

func identityError(sr *format.StanzaReader, idx int, err error) {
	protocolError(sr, []string{"identity", fmt.Sprint(idx)}, err)
}

func internalError(sr *format.StanzaReader, err error) {
	protocolError(sr, []string{"internal"}, err)
}

func protocolError(sr *format.StanzaReader, args []string, err error) {
	s := &format.Stanza{Type: "error", Args: args}
	s.Body = []byte(err.Error())
	if err := s.Marshal(os.Stdout); err != nil {
		fatalf("failed to write error stanza: %v", err)
	}
	expectOk(sr)
	os.Exit(3)
}

func expectOk(sr *format.StanzaReader) {
	ok, err := sr.ReadStanza()
	if err != nil {
		fatalf("failed to read OK stanza: %v", err)
	}
	if ok.Type != "ok" {
		fatalf("expected OK stanza, got %q", ok.Type)
	}
	expectStanzaWithNoBody(ok, 0)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}
