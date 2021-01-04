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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

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

func (r *Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	cmd := exec.Command("age-plugin-"+r.name, "--age-plugin=recipient-v1")
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	cmd.Dir = filepath.Clean("/") // TODO: does this work on Windows
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Phase 1: client sends recipient and file key
	s := &format.Stanza{
		Type: "add-recipient",
		Args: []string{r.encoding},
	}
	if err := s.Marshal(stdin); err != nil {
		return nil, err
	}

	s = &format.Stanza{
		Type: "wrap-file-key",
		Body: fileKey,
	}
	if err := s.Marshal(stdin); err != nil {
		return nil, err
	}

	s = &format.Stanza{
		Type: "done",
	}
	if err := s.Marshal(stdin); err != nil {
		return nil, err
	}

	// Phase 2: plugin responds with stanzas
	var out []*age.Stanza
	sr := format.NewStanzaReader(bufio.NewReader(stdout))
ReadLoop:
	for {
		s, err := sr.ReadStanza()
		if err != nil {
			return nil, err
		}

		switch s.Type {
		case "recipient-stanza":
			if len(s.Args) < 2 {
				return nil, fmt.Errorf("plugin error: received malformed recipient stanza")
			}
			n, err := strconv.Atoi(s.Args[0])
			if err != nil {
				return nil, fmt.Errorf("plugin error: received malformed recipient stanza")
			}
			// Currently, we only send a single file key, so the index must be 0.
			if n != 0 {
				return nil, fmt.Errorf("plugin error: received malformed recipient stanza")
			}

			out = append(out, &age.Stanza{
				Type: s.Args[1],
				Args: s.Args[2:],
				Body: s.Body,
			})
		case "error":
			return nil, fmt.Errorf("plugin error: %q", s.Body)
		case "done":
			break ReadLoop
		default:
			// Unknown commands are ignored.
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("plugin error: received zero recipient stanzas")
	}

	if err := stdin.Close(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	return out, nil
}

type Identity struct {
	name     string
	encoding string
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
	// TODO: DRY up connection management into a connection type, and defer
	// closing the connection.
	cmd := exec.Command("age-plugin-"+i.name, "--age-plugin=identity-v1")
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	cmd.Dir = filepath.Clean("/") // TODO: does this work on Windows
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Phase 1: client sends the plugin the identity string and the stanzas
	s := &format.Stanza{
		Type: "add-identity",
		Args: []string{i.encoding},
	}
	if err := s.Marshal(stdin); err != nil {
		return nil, err
	}

	for _, rs := range stanzas {
		s = &format.Stanza{
			Type: "recipient-stanza",
			Args: append([]string{"0", rs.Type}, rs.Args...),
			Body: rs.Body,
		}
		if err := s.Marshal(stdin); err != nil {
			return nil, err
		}
	}

	s = &format.Stanza{
		Type: "done",
	}
	if err := s.Marshal(stdin); err != nil {
		return nil, err
	}

	// Phase 2: plugin responds with various commands and a file key
	var out []byte
	sr := format.NewStanzaReader(bufio.NewReader(stdout))
ReadLoop:
	for {
		s, err := sr.ReadStanza()
		if err != nil {
			return nil, err
		}

		switch s.Type {
		case "msg":
			// TODO: unimplemented.
			ss := &format.Stanza{Type: "ok"}
			if err := ss.Marshal(stdin); err != nil {
				return nil, err
			}
		case "request-secret":
			// TODO: unimplemented.
			ss := &format.Stanza{Type: "fail"}
			if err := ss.Marshal(stdin); err != nil {
				return nil, err
			}
		case "file-key":
			if len(s.Args) != 1 {
				return nil, fmt.Errorf("plugin error: received malformed file-key stanza")
			}
			n, err := strconv.Atoi(s.Args[0])
			if err != nil {
				return nil, fmt.Errorf("plugin error: received malformed file-key stanza")
			}
			// Currently, we only send a single file key, so the index must be 0.
			if n != 0 {
				return nil, fmt.Errorf("plugin error: received malformed file-key stanza")
			}

			out = s.Body

			ss := &format.Stanza{Type: "ok"}
			if err := ss.Marshal(stdin); err != nil {
				return nil, err
			}
		case "error":
			ss := &format.Stanza{Type: "ok"}
			if err := ss.Marshal(stdin); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("plugin error: %q", s.Body)
		case "done":
			break ReadLoop
		default:
			// Unknown commands are ignored.
		}
	}

	if out == nil {
		return nil, age.ErrIncorrectIdentity
	}
	return out, nil
}
