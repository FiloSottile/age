// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

// NewWrappedBase64Encoder returns a WrappedBase64Encoder that writes to dst.
func NewWrappedBase64Encoder(enc *base64.Encoding, dst io.Writer) *WrappedBase64Encoder {
	w := &WrappedBase64Encoder{dst: dst}
	w.enc = base64.NewEncoder(enc, WriterFunc(w.writeWrapped))
	return w
}

type WriterFunc func(p []byte) (int, error)

func (f WriterFunc) Write(p []byte) (int, error) { return f(p) }

// WrappedBase64Encoder is a standard base64 encoder that inserts an LF
// character every ColumnsPerLine bytes. It does not insert a newline neither at
// the beginning nor at the end of the stream, but it ensures the last line is
// shorter than ColumnsPerLine, which means it might be empty.
type WrappedBase64Encoder struct {
	enc     io.WriteCloser
	dst     io.Writer
	written int
	buf     bytes.Buffer
}

func (w *WrappedBase64Encoder) Write(p []byte) (int, error) { return w.enc.Write(p) }

func (w *WrappedBase64Encoder) Close() error {
	return w.enc.Close()
}

func (w *WrappedBase64Encoder) writeWrapped(p []byte) (int, error) {
	if w.buf.Len() != 0 {
		panic("age: internal error: non-empty WrappedBase64Encoder.buf")
	}
	for len(p) > 0 {
		toWrite := ColumnsPerLine - (w.written % ColumnsPerLine)
		if toWrite > len(p) {
			toWrite = len(p)
		}
		n, _ := w.buf.Write(p[:toWrite])
		w.written += n
		p = p[n:]
		if w.written%ColumnsPerLine == 0 {
			w.buf.Write([]byte("\n"))
		}
	}
	if _, err := w.buf.WriteTo(w.dst); err != nil {
		// We always return n = 0 on error because it's hard to work back to the
		// input length that ended up written out. Not ideal, but Write errors
		// are not recoverable anyway.
		return 0, err
	}
	return len(p), nil
}

// LastLineIsEmpty returns whether the last output line was empty, either
// because no input was written, or because a multiple of BytesPerLine was.
//
// Calling LastLineIsEmpty before Close is meaningless.
func (w *WrappedBase64Encoder) LastLineIsEmpty() bool {
	return w.written%ColumnsPerLine == 0
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
	ww := NewWrappedBase64Encoder(b64, w)
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
			if r != nil {
				return nil, nil, errorf("malformed body line %q: reached footer without previous stanza being closed\nNote: this might be a file encrypted with an old beta version of rage. Use rage to decrypt it.", line)
			}
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
			if r != nil {
				return nil, nil, errorf("malformed body line %q: new stanza started without previous stanza being closed\nNote: this might be a file encrypted with an old beta version of rage. Use rage to decrypt it.", line)
			}
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
