// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package format implements the age file format.
package format

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

type Header struct {
	Recipients []*Recipient
	MAC        []byte
}

type Recipient struct {
	Type string
	Args []string
	Body []byte
}

var b64 = base64.RawStdEncoding.Strict()

func DecodeString(s string) ([]byte, error) {
	// CR and LF are ignored by DecodeString, but we don't want any malleability.
	if strings.ContainsAny(s, "\n\r") {
		return nil, errors.New(`unexpected newline character`)
	}
	return b64.DecodeString(s)
}

var EncodeToString = b64.EncodeToString

const columnsPerLine = 64
const bytesPerLine = columnsPerLine / 4 * 3

const intro = "age-encryption.org/v1\n"

var recipientPrefix = []byte("->")
var footerPrefix = []byte("---")

func (r *Recipient) Marshal(w io.Writer) error {
	if _, err := w.Write(recipientPrefix); err != nil {
		return err
	}
	for _, a := range append([]string{r.Type}, r.Args...) {
		if _, err := io.WriteString(w, " "+a); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}
	if len(r.Body) == 0 {
		return nil
	}
	ww := base64.NewEncoder(b64, &newlineWriter{dst: w})
	if _, err := ww.Write(r.Body); err != nil {
		return err
	}
	if err := ww.Close(); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func (h *Header) MarshalWithoutMAC(w io.Writer) error {
	if _, err := io.WriteString(w, intro); err != nil {
		return err
	}
	for _, r := range h.Recipients {
		if err := r.Marshal(w); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "%s", footerPrefix)
	return err
}

func (h *Header) Marshal(w io.Writer) error {
	if err := h.MarshalWithoutMAC(w); err != nil {
		return err
	}
	mac := b64.EncodeToString(h.MAC)
	_, err := fmt.Fprintf(w, " %s\n", mac)
	return err
}

type ParseError string

func (e ParseError) Error() string {
	return "parsing age header: " + string(e)
}

func errorf(format string, a ...interface{}) error {
	return ParseError(fmt.Sprintf(format, a...))
}

// Parse returns the header and a Reader that begins at the start of the
// payload.
func Parse(input io.Reader) (*Header, io.Reader, error) {
	h := &Header{}
	rr := bufio.NewReader(input)

	// TODO: find a way to communicate to the caller that the file was armored,
	// as they might not appreciate the malleability.
	if start, _ := rr.Peek(len(armorPreamble)); string(start) == armorPreamble {
		input = ArmoredReader(rr)
		rr = bufio.NewReader(input)
	}

	line, err := rr.ReadString('\n')
	if err != nil {
		return nil, nil, errorf("failed to read intro: %v", err)
	}
	if line != intro {
		return nil, nil, errorf("unexpected intro: %q", line)
	}

	var r *Recipient
	for {
		line, err := rr.ReadBytes('\n')
		if err != nil {
			return nil, nil, errorf("failed to read header: %v", err)
		}

		if bytes.HasPrefix(line, footerPrefix) {
			prefix, args := splitArgs(line)
			if prefix != string(footerPrefix) || len(args) != 1 {
				return nil, nil, errorf("malformed closing line: %q", line)
			}
			h.MAC, err = DecodeString(args[0])
			if err != nil {
				return nil, nil, errorf("malformed closing line %q: %v", line, err)
			}
			break

		} else if bytes.HasPrefix(line, recipientPrefix) {
			r = &Recipient{}
			prefix, args := splitArgs(line)
			if prefix != string(recipientPrefix) || len(args) < 1 {
				return nil, nil, errorf("malformed recipient: %q", line)
			}
			for _, a := range args {
				if !isValidString(a) {
					return nil, nil, errorf("malformed recipient: %q", line)
				}
			}
			r.Type = args[0]
			r.Args = args[1:]
			h.Recipients = append(h.Recipients, r)

		} else if r != nil {
			b, err := DecodeString(strings.TrimSuffix(string(line), "\n"))
			if err != nil {
				return nil, nil, errorf("malformed body line %q: %v", line, err)
			}
			if len(b) > bytesPerLine {
				return nil, nil, errorf("malformed body line %q: too long", line)
			}
			if len(b) == 0 {
				return nil, nil, errorf("malformed body line %q: line is empty", line)
			}
			r.Body = append(r.Body, b...)
			if len(b) < bytesPerLine {
				// Only the last line of a body can be short.
				r = nil
			}

		} else {
			return nil, nil, errorf("unexpected line: %q", line)
		}
	}

	// Unwind the bufio overread and return the unbuffered input.
	buf, err := rr.Peek(rr.Buffered())
	if err != nil {
		return nil, nil, errorf("internal error: %v", err)
	}
	payload := io.MultiReader(bytes.NewReader(buf), input)

	return h, payload, nil
}

func splitArgs(line []byte) (string, []string) {
	l := strings.TrimSuffix(string(line), "\n")
	parts := strings.Split(l, " ")
	return parts[0], parts[1:]
}

func isValidString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
