package plugin

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"filippo.io/age"
	"filippo.io/age/internal/format"
)

// TODO: add examples.

// Plugin is a framework for writing age plugins. It allows exposing regular
// [age.Recipient] and [age.Identity] implementations as plugins, and handles
// all the protocol details.
type Plugin struct {
	name string
	fs   *flag.FlagSet
	sm   *string

	recipient     func([]byte) (age.Recipient, error)
	idAsRecipient func([]byte) (age.Recipient, error)
	identity      func([]byte) (age.Identity, error)

	sr *format.StanzaReader
	// broken is set if the protocol broke down during an interaction function
	// called by a Recipient or Identity.
	broken bool
}

// New creates a new Plugin with the given name.
//
// For example, a plugin named "frood" would be invoked as "age-plugin-frood".
func New(name string) (*Plugin, error) {
	return &Plugin{name: name}, nil
}

// Name returns the name of the plugin.
func (p *Plugin) Name() string {
	return p.name
}

// RegisterFlags registers the plugin's flags with the given [flag.FlagSet], or
// with the default [flag.CommandLine] if fs is nil. It must be called before
// [flag.Parse] and [Plugin.Main].
//
// This allows the plugin to expose additional flags when invoked manually, for
// example to implement a keygen mode.
func (p *Plugin) RegisterFlags(fs *flag.FlagSet) {
	if fs == nil {
		fs = flag.CommandLine
	}
	p.fs = fs
	p.sm = fs.String("age-plugin", "", "age-plugin state machine")
}

// HandleRecipient registers a function to parse recipients of the form
// age1name1... into [age.Recipient] values. data is the decoded Bech32 payload.
//
// If the returned Recipient implements [age.RecipientWithLabels], Plugin will
// use it and enforce consistency across every returned stanza in an execution.
// If the client supports labels, they will be passed through the protocol.
//
// It must be called before [Plugin.Main], and can be called at most once.
func (p *Plugin) HandleRecipient(f func(data []byte) (age.Recipient, error)) {
	if p.recipient != nil {
		panic("HandleRecipient called twice")
	}
	p.recipient = f
}

// HandleIdentityAsRecipient registers a function to parse identities of the
// form AGE-PLUGIN-NAME-1... into [age.Recipient] values, for when identities
// are used as recipients. data is the decoded Bech32 payload.
//
// If the returned Recipient implements [age.RecipientWithLabels], Plugin will
// use it and enforce consistency across every returned stanza in an execution.
// If the client supports labels, they will be passed through the protocol.
//
// It must be called before [Plugin.Main], and can be called at most once.
func (p *Plugin) HandleIdentityAsRecipient(f func(data []byte) (age.Recipient, error)) {
	if p.idAsRecipient != nil {
		panic("HandleIdentityAsRecipient called twice")
	}
	p.idAsRecipient = f
}

// HandleIdentity registers a function to parse identities of the form
// AGE-PLUGIN-NAME-1... into [age.Identity] values. data is the decoded Bech32
// payload.
//
// It must be called before [Plugin.Main], and can be called at most once.
func (p *Plugin) HandleIdentity(f func(data []byte) (age.Identity, error)) {
	if p.identity != nil {
		panic("HandleIdentity called twice")
	}
	p.identity = f
}

// Main runs the plugin protocol over stdin/stdout, and writes errors to stderr.
// It returns an exit code to pass to os.Exit.
//
// It automatically calls [Plugin.RegisterFlags] and [flag.Parse] if they were
// not called before.
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

// RecipientV1 implements the recipient-v1 state machine over stdin/stdout, and
// writes errors to stderr. It returns an exit code to pass to os.Exit.
//
// Most plugins should call [Plugin.Main] instead of this method.
func (p *Plugin) RecipientV1() int {
	if p.recipient == nil && p.idAsRecipient == nil {
		return fatalf("recipient-v1 not supported")
	}

	var recipientStrings, identityStrings []string
	var fileKeys [][]byte
	var supportsLabels bool

	p.sr = format.NewStanzaReader(bufio.NewReader(os.Stdin))
ReadLoop:
	for {
		s, err := p.sr.ReadStanza()
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
			return recipientError(p.sr, i, err)
		}
		if name != p.name {
			return recipientError(p.sr, i, fmt.Errorf("unsupported plugin name: %q", name))
		}
		if p.recipient == nil {
			return recipientError(p.sr, i, fmt.Errorf("recipient encodings not supported"))
		}
		r, err := p.recipient(data)
		if err != nil {
			return recipientError(p.sr, i, err)
		}
		recipients = append(recipients, r)
	}
	for i, s := range identityStrings {
		name, data, err := ParseIdentity(s)
		if err != nil {
			return identityError(p.sr, i, err)
		}
		if name != p.name {
			return identityError(p.sr, i, fmt.Errorf("unsupported plugin name: %q", name))
		}
		if p.idAsRecipient == nil {
			return identityError(p.sr, i, fmt.Errorf("identity encodings not supported"))
		}
		r, err := p.idAsRecipient(data)
		if err != nil {
			return identityError(p.sr, i, err)
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
			if p.broken {
				return 2
			} else if err != nil {
				return recipientError(p.sr, j, err)
			}
			if i == 0 && j == 0 {
				labels = ll
			} else if err := checkLabels(ll, labels); err != nil {
				return recipientError(p.sr, j, err)
			}
			stanzas[i] = append(stanzas[i], ss...)
		}
		for j, r := range identities {
			ss, ll, err := wrapWithLabels(r, fk)
			if p.broken {
				return 2
			} else if err != nil {
				return identityError(p.sr, j, err)
			}
			if i == 0 && j == 0 && len(recipients) == 0 {
				labels = ll
			} else if err := checkLabels(ll, labels); err != nil {
				return identityError(p.sr, j, err)
			}
			stanzas[i] = append(stanzas[i], ss...)
		}
	}

	if sent, err := writeGrease(os.Stdout); err != nil {
		return fatalf("failed to write grease: %v", err)
	} else if sent {
		if err := expectUnsupported(p.sr); err != nil {
			return fatalf("%v", err)
		}
	}

	if supportsLabels {
		if err := writeStanza(os.Stdout, "labels", labels...); err != nil {
			return fatalf("failed to write labels stanza: %v", err)
		}
		if err := expectOk(p.sr); err != nil {
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
			if err := expectOk(p.sr); err != nil {
				return fatalf("%v", err)
			}
		}
		if sent, err := writeGrease(os.Stdout); err != nil {
			return fatalf("failed to write grease: %v", err)
		} else if sent {
			if err := expectUnsupported(p.sr); err != nil {
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

// IdentityV1 implements the identity-v1 state machine over stdin/stdout, and
// writes errors to stderr. It returns an exit code to pass to os.Exit.
//
// Most plugins should call [Plugin.Main] instead of this method.
func (p *Plugin) IdentityV1() int {
	if p.identity == nil {
		return fatalf("identity-v1 not supported")
	}

	var files [][]*age.Stanza
	var identityStrings []string

	p.sr = format.NewStanzaReader(bufio.NewReader(os.Stdin))
ReadLoop:
	for {
		s, err := p.sr.ReadStanza()
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
			return identityError(p.sr, i, err)
		}
		if name != p.name {
			return identityError(p.sr, i, fmt.Errorf("unsupported plugin name: %q", name))
		}
		if p.identity == nil {
			return identityError(p.sr, i, fmt.Errorf("identity encodings not supported"))
		}
		r, err := p.identity(data)
		if err != nil {
			return identityError(p.sr, i, err)
		}
		identities = append(identities, r)
	}

	for i, ss := range files {
		if sent, err := writeGrease(os.Stdout); err != nil {
			return fatalf("failed to write grease: %v", err)
		} else if sent {
			if err := expectUnsupported(p.sr); err != nil {
				return fatalf("%v", err)
			}
		}

		// TODO: there should be a mechanism to let the plugin decide the order
		// in which identities are tried.
		for _, id := range identities {
			fk, err := id.Unwrap(ss)
			if p.broken {
				return 2
			} else if errors.Is(err, age.ErrIncorrectIdentity) {
				continue
			} else if err != nil {
				if err := writeError(p.sr, []string{"stanza", fmt.Sprint(i), "0"}, err); err != nil {
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
			if err := expectOk(p.sr); err != nil {
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

// DisplayMessage requests that the client display a message to the user. The
// message should start with a lowercase letter and have no final period.
// DisplayMessage returns an error if the client can't display the message, and
// may return before the message has been displayed to the user.
//
// It must only be called by a Wrap or Unwrap method invoked by [Plugin.Main].
func (p *Plugin) DisplayMessage(message string) error {
	if err := writeStanzaWithBody(os.Stdout, "msg", []byte(message)); err != nil {
		return p.fatalInteractf("failed to write msg stanza: %v", err)
	}
	s, err := readOkOrFail(p.sr)
	if err != nil {
		return p.fatalInteractf("%v", err)
	}
	if s.Type == "fail" {
		return fmt.Errorf("client failed to display message")
	}
	return nil
}

// RequestValue requests a secret or public input from the user through the
// client, with the provided prompt. It returns an error if the client can't
// request the input or if the user dismisses the prompt.
//
// It must only be called by a Wrap or Unwrap method invoked by [Plugin.Main].
func (p *Plugin) RequestValue(prompt string, secret bool) (string, error) {
	t := "request-public"
	if secret {
		t = "request-secret"
	}
	if err := writeStanzaWithBody(os.Stdout, t, []byte(prompt)); err != nil {
		return "", p.fatalInteractf("failed to write stanza: %v", err)
	}
	s, err := readOkOrFail(p.sr)
	if err != nil {
		return "", p.fatalInteractf("%v", err)
	}
	if s.Type == "fail" {
		return "", fmt.Errorf("client failed to request value")
	}
	return string(s.Body), nil
}

// Confirm requests a confirmation from the user through the client, with the
// provided prompt. The yes and no value are the choices provided to the user.
// no may be empty. The return value choseYes indicates whether the user
// selected the yes or no option. Confirm returns an error if the client can't
// request the confirmation.
//
// It must only be called by a Wrap or Unwrap method invoked by [Plugin.Main].
func (p *Plugin) Confirm(prompt, yes, no string) (choseYes bool, err error) {
	args := []string{base64.StdEncoding.EncodeToString([]byte(yes))}
	if no != "" {
		args = append(args, base64.StdEncoding.EncodeToString([]byte(no)))
	}
	s := &format.Stanza{Type: "confirm", Args: args, Body: []byte(prompt)}
	if err := s.Marshal(os.Stdout); err != nil {
		return false, p.fatalInteractf("failed to write confirm stanza: %v", err)
	}
	s, err = readOkOrFail(p.sr)
	if err != nil {
		return false, p.fatalInteractf("%v", err)
	}
	if s.Type == "fail" {
		return false, fmt.Errorf("client failed to request confirmation")
	}
	if err := expectStanzaWithNoBody(s, 1); err != nil {
		return false, p.fatalInteractf("%v", err)
	}
	return s.Args[0] == "yes", nil
}

// fatalInteractf prints the error to stderr and sets the broken flag, so the
// Wrap/Unwrap caller can exit with an error.
func (p *Plugin) fatalInteractf(format string, args ...interface{}) error {
	p.broken = true
	fmt.Fprintf(os.Stderr, format, args...)
	return fmt.Errorf(format, args...)
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

func readOkOrFail(sr *format.StanzaReader) (*format.Stanza, error) {
	s, err := sr.ReadStanza()
	if err != nil {
		return nil, fmt.Errorf("failed to read response stanza: %v", err)
	}
	switch s.Type {
	case "fail":
		if err := expectStanzaWithNoBody(s, 0); err != nil {
			return nil, fmt.Errorf("%v", err)
		}
		return s, nil
	case "ok":
		if s.Body != nil {
			return nil, fmt.Errorf("ok stanza has %d bytes of body, want 0", len(s.Body))
		}
		return s, nil
	default:
		return nil, fmt.Errorf("expected ok or fail stanza, got %q", s.Type)
	}
}

func expectUnsupported(sr *format.StanzaReader) error {
	unsupported, err := sr.ReadStanza()
	if err != nil {
		return fmt.Errorf("failed to read unsupported stanza: %v", err)
	}
	if unsupported.Type != "unsupported" {
		return fmt.Errorf("expected unsupported stanza, got %q", unsupported.Type)
	}
	return expectStanzaWithNoBody(unsupported, 0)
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
