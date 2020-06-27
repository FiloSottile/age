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
	Recipients []*Stanza
	MAC        []byte
}

// Stanza is assignable to age.Stanza, and if this package is made public,
// age.Stanza can be made a type alias of this type.
type Stanza struct {
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

const ColumnsPerLine = 64
const BytesPerLine = ColumnsPerLine / 4 * 3

// NewlineWriter returns a Writer that writes to dst, inserting an LF character
// every ColumnsPerLine bytes. It does not insert a newline neither at the
// beginning nor at the end of the stream.
func NewlineWriter(dst io.Writer) io.Writer {
	return &newlineWriter{dst: dst}
}

type newlineWriter struct {
	dst     io.Writer
	written int
}

func (w *newlineWriter) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		remainingInLine := ColumnsPerLine - (w.written % ColumnsPerLine)
		if remainingInLine == ColumnsPerLine && w.written != 0 {
			if _, err := w.dst.Write([]byte("\n")); err != nil {
				return n, err
			}
		}
		toWrite := remainingInLine
		if toWrite > len(p) {
			toWrite = len(p)
		}
		nn, err := w.dst.Write(p[:toWrite])
		n += nn
		w.written += nn
		p = p[nn:]
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

const intro = "age-encryption.org/v1\n"

var recipientPrefix = []byte("->")
var footerPrefix = []byte("---")

func (r *Stanza) Marshal(w io.Writer) error {
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
	ww := base64.NewEncoder(b64, NewlineWriter(w))
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

	line, err := rr.ReadString('\n')
	if err != nil {
		return nil, nil, errorf("failed to read intro: %v", err)
	}
	if line != intro {
		return nil, nil, errorf("unexpected intro: %q", line)
	}

	var r *Stanza
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
			r = &Stanza{}
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
			if len(b) > BytesPerLine {
				return nil, nil, errorf("malformed body line %q: too long", line)
			}
			if len(b) == 0 {
				return nil, nil, errorf("malformed body line %q: line is empty", line)
			}
			r.Body = append(r.Body, b...)
			if len(b) < BytesPerLine {
				// Only the last line of a body can be short.
				r = nil
			}

		} else {
			return nil, nil, errorf("unexpected line: %q", line)
		}
	}

	// If input is a bufio.Reader, rr might be equal to input because
	// bufio.NewReader short-circuits. In this case we can just return it (and
	// we would end up reading the buffer twice if we prepended the peek below).
	if rr == input {
		return h, rr, nil
	}
	// Otherwise, unwind the bufio overread and return the unbuffered input.
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
