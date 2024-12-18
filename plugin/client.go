// Copyright 2021 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package plugin implements the age plugin protocol.
package plugin

import (
	"bufio"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	exec "golang.org/x/sys/execabs"

	"filippo.io/age"
	"filippo.io/age/internal/format"
)

type Recipient struct {
	name     string
	encoding string
	ui       *ClientUI

	// identity is true when encoding is an identity string.
	identity bool
}

var _ age.Recipient = &Recipient{}
var _ age.RecipientWithLabels = &Recipient{}

func NewRecipient(s string, ui *ClientUI) (*Recipient, error) {
	name, _, err := ParseRecipient(s)
	if err != nil {
		return nil, err
	}
	return &Recipient{
		name: name, encoding: s, ui: ui,
	}, nil
}

// Name returns the plugin name, which is used in the recipient ("age1name1...")
// and identity ("AGE-PLUGIN-NAME-1...") encodings, as well as in the plugin
// binary name ("age-plugin-name").
func (r *Recipient) Name() string {
	return r.name
}

func (r *Recipient) Wrap(fileKey []byte) (stanzas []*age.Stanza, err error) {
	stanzas, _, err = r.WrapWithLabels(fileKey)
	return
}

func (r *Recipient) WrapWithLabels(fileKey []byte) (stanzas []*age.Stanza, labels []string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%s plugin: %w", r.name, err)
		}
	}()

	conn, err := openClientConnection(r.name, "recipient-v1")
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't start plugin: %v", err)
	}
	defer conn.Close()

	// Phase 1: client sends recipient or identity and file key
	addType := "add-recipient"
	if r.identity {
		addType = "add-identity"
	}
	if err := writeStanza(conn, addType, r.encoding); err != nil {
		return nil, nil, err
	}
	if err := writeStanza(conn, fmt.Sprintf("grease-%x", rand.Int())); err != nil {
		return nil, nil, err
	}
	if err := writeStanzaWithBody(conn, "wrap-file-key", fileKey); err != nil {
		return nil, nil, err
	}
	if err := writeStanza(conn, "extension-labels"); err != nil {
		return nil, nil, err
	}
	if err := writeStanza(conn, "done"); err != nil {
		return nil, nil, err
	}

	// Phase 2: plugin responds with stanzas
	sr := format.NewStanzaReader(bufio.NewReader(conn))
ReadLoop:
	for {
		s, err := r.ui.readStanza(r.name, sr)
		if err != nil {
			return nil, nil, err
		}

		switch s.Type {
		case "recipient-stanza":
			if len(s.Args) < 2 {
				return nil, nil, fmt.Errorf("malformed recipient stanza: unexpected argument count")
			}
			n, err := strconv.Atoi(s.Args[0])
			if err != nil {
				return nil, nil, fmt.Errorf("malformed recipient stanza: invalid index")
			}
			// We only send a single file key, so the index must be 0.
			if n != 0 {
				return nil, nil, fmt.Errorf("malformed recipient stanza: unexpected index")
			}

			stanzas = append(stanzas, &age.Stanza{
				Type: s.Args[1],
				Args: s.Args[2:],
				Body: s.Body,
			})

			if err := writeStanza(conn, "ok"); err != nil {
				return nil, nil, err
			}
		case "labels":
			if labels != nil {
				return nil, nil, fmt.Errorf("repeated labels stanza")
			}
			labels = s.Args

			if err := writeStanza(conn, "ok"); err != nil {
				return nil, nil, err
			}
		case "error":
			if err := writeStanza(conn, "ok"); err != nil {
				return nil, nil, err
			}

			return nil, nil, fmt.Errorf("%s", s.Body)
		case "done":
			break ReadLoop
		default:
			if ok, err := r.ui.handle(r.name, conn, s); err != nil {
				return nil, nil, err
			} else if !ok {
				if err := writeStanza(conn, "unsupported"); err != nil {
					return nil, nil, err
				}
			}
		}
	}

	if len(stanzas) == 0 {
		return nil, nil, fmt.Errorf("received zero recipient stanzas")
	}

	return stanzas, labels, nil
}

type Identity struct {
	name     string
	encoding string
	ui       *ClientUI
}

var _ age.Identity = &Identity{}

func NewIdentity(s string, ui *ClientUI) (*Identity, error) {
	name, _, err := ParseIdentity(s)
	if err != nil {
		return nil, err
	}
	return &Identity{
		name: name, encoding: s, ui: ui,
	}, nil
}

func NewIdentityWithoutData(name string, ui *ClientUI) (*Identity, error) {
	s := EncodeIdentity(name, nil)
	if s == "" {
		return nil, fmt.Errorf("invalid plugin name: %q", name)
	}
	return &Identity{
		name: name, encoding: s, ui: ui,
	}, nil
}

// Name returns the plugin name, which is used in the recipient ("age1name1...")
// and identity ("AGE-PLUGIN-NAME-1...") encodings, as well as in the plugin
// binary name ("age-plugin-name").
func (i *Identity) Name() string {
	return i.name
}

// Recipient returns a Recipient wrapping this identity. When that Recipient is
// used to encrypt a file key, the identity encoding is provided as-is to the
// plugin, which is expected to support encrypting to identities.
func (i *Identity) Recipient() *Recipient {
	return &Recipient{
		name:     i.name,
		encoding: i.encoding,
		identity: true,
		ui:       i.ui,
	}
}

func (i *Identity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%s plugin: %w", i.name, err)
		}
	}()

	conn, err := openClientConnection(i.name, "identity-v1")
	if err != nil {
		return nil, fmt.Errorf("couldn't start plugin: %v", err)
	}
	defer conn.Close()

	// Phase 1: client sends the plugin the identity string and the stanzas
	if err := writeStanza(conn, "add-identity", i.encoding); err != nil {
		return nil, err
	}
	if err := writeStanza(conn, fmt.Sprintf("grease-%x", rand.Int())); err != nil {
		return nil, err
	}
	for _, rs := range stanzas {
		s := &format.Stanza{
			Type: "recipient-stanza",
			Args: append([]string{"0", rs.Type}, rs.Args...),
			Body: rs.Body,
		}
		if err := s.Marshal(conn); err != nil {
			return nil, err
		}
	}
	if err := writeStanza(conn, "done"); err != nil {
		return nil, err
	}

	// Phase 2: plugin responds with various commands and a file key
	sr := format.NewStanzaReader(bufio.NewReader(conn))
ReadLoop:
	for {
		s, err := i.ui.readStanza(i.name, sr)
		if err != nil {
			return nil, err
		}

		switch s.Type {
		case "file-key":
			if len(s.Args) != 1 {
				return nil, fmt.Errorf("malformed file-key stanza: unexpected arguments count")
			}
			n, err := strconv.Atoi(s.Args[0])
			if err != nil {
				return nil, fmt.Errorf("malformed file-key stanza: invalid index")
			}
			// We only send a single file key, so the index must be 0.
			if n != 0 {
				return nil, fmt.Errorf("malformed file-key stanza: unexpected index")
			}
			if fileKey != nil {
				return nil, fmt.Errorf("received duplicated file-key stanza")
			}

			fileKey = s.Body

			if err := writeStanza(conn, "ok"); err != nil {
				return nil, err
			}
		case "error":
			if err := writeStanza(conn, "ok"); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%s", s.Body)
		case "done":
			break ReadLoop
		default:
			if ok, err := i.ui.handle(i.name, conn, s); err != nil {
				return nil, err
			} else if !ok {
				if err := writeStanza(conn, "unsupported"); err != nil {
					return nil, err
				}
			}
		}
	}

	if fileKey == nil {
		return nil, age.ErrIncorrectIdentity
	}
	return fileKey, nil
}

// ClientUI holds callbacks that will be invoked by (Un)Wrap if the plugin
// wishes to interact with the user. If any of them is nil or returns an error,
// failure will be reported to the plugin, but note that the error is otherwise
// discarded. Implementations are encouraged to display errors to the user
// before returning them.
type ClientUI struct {
	// DisplayMessage displays the message, which is expected to have lowercase
	// initials and no final period.
	DisplayMessage func(name, message string) error

	// RequestValue requests a secret or public input, with the provided prompt.
	RequestValue func(name, prompt string, secret bool) (string, error)

	// Confirm requests a confirmation with the provided prompt. The yes and no
	// value are the choices provided to the user. no may be empty. The return
	// value indicates whether the user selected the yes or no option.
	Confirm func(name, prompt, yes, no string) (choseYes bool, err error)

	// WaitTimer is invoked once (Un)Wrap has been waiting for 5 seconds on the
	// plugin, for example because the plugin is waiting for an external event
	// (e.g. a hardware token touch). Unlike the other callbacks, WaitTimer runs
	// in a separate goroutine, and if missing it's simply ignored.
	WaitTimer func(name string)
}

func (c *ClientUI) handle(name string, conn *clientConnection, s *format.Stanza) (ok bool, err error) {
	switch s.Type {
	case "msg":
		if c.DisplayMessage == nil {
			return true, writeStanza(conn, "fail")
		}
		if err := c.DisplayMessage(name, string(s.Body)); err != nil {
			return true, writeStanza(conn, "fail")
		}
		return true, writeStanza(conn, "ok")
	case "request-secret", "request-public":
		if c.RequestValue == nil {
			return true, writeStanza(conn, "fail")
		}
		secret, err := c.RequestValue(name, string(s.Body), s.Type == "request-secret")
		if err != nil {
			return true, writeStanza(conn, "fail")
		}
		return true, writeStanzaWithBody(conn, "ok", []byte(secret))
	case "confirm":
		if len(s.Args) != 1 && len(s.Args) != 2 {
			return true, fmt.Errorf("malformed confirm stanza: unexpected number of arguments")
		}
		if c.Confirm == nil {
			return true, writeStanza(conn, "fail")
		}
		yes, err := format.DecodeString(s.Args[0])
		if err != nil {
			return true, fmt.Errorf("malformed confirm stanza: invalid YES option encoding")
		}
		var no []byte
		if len(s.Args) == 2 {
			no, err = format.DecodeString(s.Args[1])
			if err != nil {
				return true, fmt.Errorf("malformed confirm stanza: invalid NO option encoding")
			}
		}
		choseYes, err := c.Confirm(name, string(s.Body), string(yes), string(no))
		if err != nil {
			return true, writeStanza(conn, "fail")
		}
		result := "yes"
		if !choseYes {
			result = "no"
		}
		return true, writeStanza(conn, "ok", result)
	default:
		return false, nil
	}
}

// readStanza calls r.ReadStanza and, if set, invokes WaitTimer in a separate
// goroutine if the call takes longer than 5 seconds.
func (c *ClientUI) readStanza(name string, r *format.StanzaReader) (*format.Stanza, error) {
	if c.WaitTimer != nil {
		defer time.AfterFunc(5*time.Second, func() { c.WaitTimer(name) }).Stop()
	}
	return r.ReadStanza()
}

type clientConnection struct {
	cmd       *exec.Cmd
	io.Reader // stdout
	io.Writer // stdin
	close     func()
}

var testOnlyPluginPath string

func openClientConnection(name, protocol string) (*clientConnection, error) {
	path := "age-plugin-" + name
	if testOnlyPluginPath != "" {
		path = filepath.Join(testOnlyPluginPath, path)
	} else if strings.ContainsRune(name, os.PathSeparator) {
		return nil, fmt.Errorf("invalid plugin name: %q", name)
	}
	cmd := exec.Command(path, "--age-plugin="+protocol)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	cc := &clientConnection{
		cmd:    cmd,
		Reader: stdout,
		Writer: stdin,
		close: func() {
			stdin.Close()
			stdout.Close()
		},
	}

	if os.Getenv("AGEDEBUG") == "plugin" {
		cc.Reader = io.TeeReader(cc.Reader, os.Stderr)
		cc.Writer = io.MultiWriter(cc.Writer, os.Stderr)
		cmd.Stderr = os.Stderr
	}

	// We don't want the plugins to rely on the working directory for anything
	// as different clients might treat it differently, so we set it to an empty
	// temporary directory.
	cmd.Dir = os.TempDir()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return cc, nil
}

func (cc *clientConnection) Close() error {
	// Close stdin and stdout and send SIGINT (if supported) to the plugin,
	// then wait for it to cleanup and exit.
	cc.close()
	cc.cmd.Process.Signal(os.Interrupt)
	return cc.cmd.Wait()
}

func writeStanza(conn io.Writer, t string, args ...string) error {
	s := &format.Stanza{Type: t, Args: args}
	return s.Marshal(conn)
}

func writeStanzaWithBody(conn io.Writer, t string, body []byte) error {
	s := &format.Stanza{Type: t, Body: body}
	return s.Marshal(conn)
}
