// Copyright 2021 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package plugin implements the age plugin protocol.
package plugin

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	exec "golang.org/x/sys/execabs"

	"filippo.io/age"
	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/format"
)

type Recipient struct {
	name     string
	encoding string
}

var _ age.Recipient = &Recipient{}

func NewRecipient(s string) (*Recipient, error) {
	hrp, _, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient encoding %q: %v", s, err)
	}
	if !strings.HasPrefix(hrp, "age1") {
		return nil, fmt.Errorf("not a plugin recipient %q: %v", s, err)
	}
	name := strings.TrimPrefix(hrp, "age1")
	return &Recipient{
		name: name, encoding: s,
	}, nil
}

// Name returns the plugin name, which is used in the recipient ("age1name1...")
// and identity ("AGE-PLUGIN-NAME-1...") encodings, as well as in the plugin
// binary name ("age-plugin-name").
func (r *Recipient) Name() string {
	return r.name
}

func (r *Recipient) Wrap(fileKey []byte) (stanzas []*age.Stanza, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("age-plugin-%s: %w", r.name, err)
		}
	}()

	conn, err := openClientConnection(r.name, "recipient-v1")
	if err != nil {
		return nil, fmt.Errorf("couldn't start plugin: %v", err)
	}
	defer conn.Close()

	// Phase 1: client sends recipient and file key
	s := &format.Stanza{
		Type: "add-recipient",
		Args: []string{r.encoding},
	}
	if err := s.Marshal(conn); err != nil {
		return nil, err
	}

	s = &format.Stanza{
		Type: "wrap-file-key",
		Body: fileKey,
	}
	if err := s.Marshal(conn); err != nil {
		return nil, err
	}

	s = &format.Stanza{
		Type: "done",
	}
	if err := s.Marshal(conn); err != nil {
		return nil, err
	}

	// Phase 2: plugin responds with stanzas
	sr := format.NewStanzaReader(bufio.NewReader(conn))
ReadLoop:
	for {
		s, err := sr.ReadStanza()
		if err != nil {
			return nil, err
		}

		switch s.Type {
		case "recipient-stanza":
			if len(s.Args) < 2 {
				return nil, fmt.Errorf("received malformed recipient stanza")
			}
			n, err := strconv.Atoi(s.Args[0])
			if err != nil {
				return nil, fmt.Errorf("received malformed recipient stanza")
			}
			// We only send a single file key, so the index must be 0.
			if n != 0 {
				return nil, fmt.Errorf("received malformed recipient stanza")
			}

			stanzas = append(stanzas, &age.Stanza{
				Type: s.Args[1],
				Args: s.Args[2:],
				Body: s.Body,
			})
		case "error":
			return nil, fmt.Errorf("%q", s.Body)
		case "done":
			break ReadLoop
		default:
			// Unknown commands are ignored.
		}
	}

	if len(stanzas) == 0 {
		return nil, fmt.Errorf("received zero recipient stanzas")
	}

	return stanzas, nil
}

type Identity struct {
	name     string
	encoding string

	// DisplayMessage is a callback that will be invoked by Unwrap if the plugin
	// wishes to display a message to the user. If DisplayMessage is nil or
	// returns an error, failure will be reported to the plugin.
	DisplayMessage func(message string) error
	// RequestSecret is a callback that will be invoked by Unwrap if the plugin
	// wishes to request a secret from the user. If RequestSecret is nil or
	// returns an error, failure will be reported to the plugin.
	RequestSecret func(message string) (string, error)
}

var _ age.Identity = &Identity{}

func NewIdentity(s string) (*Identity, error) {
	hrp, _, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("invalid identity encoding: %v", err)
	}
	if !strings.HasPrefix(hrp, "AGE-PLUGIN-") || !strings.HasSuffix(hrp, "-") {
		return nil, fmt.Errorf("not a plugin identity: %v", err)
	}
	name := strings.TrimSuffix(strings.TrimPrefix(hrp, "AGE-PLUGIN-"), "-")
	name = strings.ToLower(name)
	return &Identity{
		name: name, encoding: s,
	}, nil
}

// Name returns the plugin name, which is used in the recipient ("age1name1...")
// and identity ("AGE-PLUGIN-NAME-1...") encodings, as well as in the plugin
// binary name ("age-plugin-name").
func (i *Identity) Name() string {
	return i.name
}

func (i *Identity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("age-plugin-%s: %w", i.name, err)
		}
	}()

	conn, err := openClientConnection(i.name, "identity-v1")
	if err != nil {
		return nil, fmt.Errorf("couldn't start plugin: %v", err)
	}
	defer conn.Close()

	// Phase 1: client sends the plugin the identity string and the stanzas
	s := &format.Stanza{
		Type: "add-identity",
		Args: []string{i.encoding},
	}
	if err := s.Marshal(conn); err != nil {
		return nil, err
	}

	for _, rs := range stanzas {
		s = &format.Stanza{
			Type: "recipient-stanza",
			Args: append([]string{"0", rs.Type}, rs.Args...),
			Body: rs.Body,
		}
		if err := s.Marshal(conn); err != nil {
			return nil, err
		}
	}

	s = &format.Stanza{
		Type: "done",
	}
	if err := s.Marshal(conn); err != nil {
		return nil, err
	}

	// Phase 2: plugin responds with various commands and a file key
	sr := format.NewStanzaReader(bufio.NewReader(conn))
ReadLoop:
	for {
		s, err := sr.ReadStanza()
		if err != nil {
			return nil, err
		}

		switch s.Type {
		case "msg":
			if i.DisplayMessage == nil {
				ss := &format.Stanza{Type: "fail"}
				if err := ss.Marshal(conn); err != nil {
					return nil, err
				}
				break
			}
			if err := i.DisplayMessage(string(s.Body)); err != nil {
				ss := &format.Stanza{Type: "fail"}
				if err := ss.Marshal(conn); err != nil {
					return nil, err
				}
			} else {
				ss := &format.Stanza{Type: "ok"}
				if err := ss.Marshal(conn); err != nil {
					return nil, err
				}
			}
		case "request-secret":
			if i.RequestSecret == nil {
				ss := &format.Stanza{Type: "fail"}
				if err := ss.Marshal(conn); err != nil {
					return nil, err
				}
				break
			}
			if secret, err := i.RequestSecret(string(s.Body)); err != nil {
				ss := &format.Stanza{Type: "fail"}
				if err := ss.Marshal(conn); err != nil {
					return nil, err
				}
			} else {
				ss := &format.Stanza{Type: "ok", Body: []byte(secret)}
				if err := ss.Marshal(conn); err != nil {
					return nil, err
				}
			}
		case "file-key":
			if len(s.Args) != 1 {
				return nil, fmt.Errorf("received malformed file-key stanza")
			}
			n, err := strconv.Atoi(s.Args[0])
			if err != nil {
				return nil, fmt.Errorf("received malformed file-key stanza")
			}
			// We only send a single file key, so the index must be 0.
			if n != 0 {
				return nil, fmt.Errorf("received malformed file-key stanza")
			}
			if fileKey != nil {
				return nil, fmt.Errorf("received duplicated file-key stanza")
			}

			fileKey = s.Body

			ss := &format.Stanza{Type: "ok"}
			if err := ss.Marshal(conn); err != nil {
				return nil, err
			}
		case "error":
			ss := &format.Stanza{Type: "ok"}
			if err := ss.Marshal(conn); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%q", s.Body)
		case "done":
			break ReadLoop
		default:
			// Unknown commands are ignored.
		}
	}

	if fileKey == nil {
		return nil, age.ErrIncorrectIdentity
	}
	return fileKey, nil
}

type clientConnection struct {
	cmd    *exec.Cmd
	stderr bytes.Buffer
	stdin  io.Closer
	stdout io.Closer
	io.Reader
	io.Writer
}

func openClientConnection(name, protocol string) (*clientConnection, error) {
	cmd := exec.Command("age-plugin-"+name, "--age-plugin="+protocol)

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
		stdout: stdout,
		Writer: stdin,
		stdin:  stdin,
	}

	cmd.Stderr = &cc.stderr

	cmd.Dir = os.TempDir()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return cc, nil
}

func (cc *clientConnection) Close() error {
	// Close stdin and stdout and send SIGINT (if supported) to the plugin,
	// then wait for it to cleanup and exit.
	cc.stdin.Close()
	cc.stdout.Close()
	cc.cmd.Process.Signal(os.Interrupt)
	return cc.cmd.Wait()
}
