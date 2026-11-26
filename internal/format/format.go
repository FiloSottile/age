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
	total := len(p)
	for len(p) > 0 {
		toWrite := min(ColumnsPerLine-(w.written%ColumnsPerLine), len(p))
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
	return total, nil
}

// LastLineIsEmpty returns whether the last output line was empty, either
// because no input was written, or because a multiple of BytesPerLine was.
//
// Calling LastLineIsEmpty before Close is meaningless.
func (w *WrappedBase64Encoder) LastLineIsEmpty() bool {
	return w.written%ColumnsPerLine == 0
}

const intro = "age-encryption.org/v1\n"

var stanzaPrefix = []byte("->")
var footerPrefix = []byte("---")

func (r *Stanza) Marshal(w io.Writer) error {
	if !isValidString(r.Type) {
		return fmt.Errorf("invalid stanza type: %q", r.Type)
	}
	for _, a := range r.Args {
		if !isValidString(a) {
			return fmt.Errorf("invalid stanza argument: %q", a)
		}
	}
	if _, err := w.Write(stanzaPrefix); err != nil {
		return err
	}
	if _, err := io.WriteString(w, " "+r.Type); err != nil {
		return err
	}
	for _, a := range r.Args {
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
	if len(h.Recipients) == 0 {
		return errors.New("no recipient stanzas")
	}
	if len(h.Recipients) > maxRecipientStanzas {
		return fmt.Errorf("too many recipient stanzas: maximum is %d", maxRecipientStanzas)
	}
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

type StanzaReader struct {
	r interface {
		ReadBytes(delim byte) ([]byte, error)
	}
	err error
}

func NewStanzaReader(r *bufio.Reader) *StanzaReader {
	return &StanzaReader{r: r}
}

func (r *StanzaReader) ReadStanza() (s *Stanza, err error) {
	// Read errors are unrecoverable.
	if r.err != nil {
		return nil, r.err
	}
	defer func() { r.err = err }()

	s = &Stanza{}

	line, err := r.r.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read line: %w", err)
	}
	if !bytes.HasPrefix(line, stanzaPrefix) {
		return nil, fmt.Errorf("malformed stanza opening line: %q", line)
	}
	prefix, args := splitArgs(line)
	if prefix != string(stanzaPrefix) || len(args) < 1 {
		return nil, fmt.Errorf("malformed stanza: %q", line)
	}
	s.Type = args[0]
	s.Args = args[1:]

	for {
		line, err := r.r.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read line: %w", err)
		}

		b, err := DecodeString(strings.TrimSuffix(string(line), "\n"))
		if err != nil {
			if bytes.HasPrefix(line, footerPrefix) || bytes.HasPrefix(line, stanzaPrefix) {
				return nil, fmt.Errorf("malformed body line %q: stanza ended without a short line\nnote: this might be a file encrypted with an old beta version of age or rage; use age v1.0.0-beta6 or rage to decrypt it", line)
			}
			return nil, errorf("malformed body line %q: %v", line, err)
		}
		if len(b) > BytesPerLine {
			return nil, errorf("malformed body line %q: too long", line)
		}
		s.Body = append(s.Body, b...)
		if len(b) < BytesPerLine {
			// A stanza body always ends with a short line.
			return s, nil
		}
	}
}

type ParseError struct {
	err error
}

const (
	maxHeaderBytes      = 2 << 20
	maxRecipientStanzas = 1024
	maxStanzaArgs       = 128
)

type headerReader struct {
	r *bufio.Reader
	n int
}

func (r *headerReader) ReadBytes(delim byte) ([]byte, error) {
	var line []byte
	for {
		frag, err := r.r.ReadSlice(delim)
		if len(frag) > maxHeaderBytes-r.n {
			return nil, errorf("header exceeds 2 MiB")
		}
		r.n += len(frag)
		line = append(line, frag...)
		if err != bufio.ErrBufferFull {
			return line, err
		}
	}
}

func (r *headerReader) ReadString(delim byte) (string, error) {
	line, err := r.ReadBytes(delim)
	return string(line), err
}

func (r *headerReader) Peek(n int) ([]byte, error) {
	if r.n+n > maxHeaderBytes {
		return nil, errorf("header exceeds 2 MiB")
	}
	return r.r.Peek(n)
}

func (e *ParseError) Error() string {
	return "parsing age header: " + e.err.Error()
}

func (e *ParseError) Unwrap() error {
	return e.err
}

func errorf(format string, a ...any) error {
	return &ParseError{fmt.Errorf(format, a...)}
}

// describeIntro returns a quoted description of a bad intro line, or an empty
// string if the line contains recognizable private key material.
func describeIntro(line string) string {
	for _, prefix := range []string{"AGE-SECRET-KEY-", "AGE-PLUGIN-"} {
		if strings.HasPrefix(line, prefix) {
			return ""
		}
	}
	// Preserve enough context to diagnose a mangled intro without echoing an
	// arbitrarily long first line.
	return fmt.Sprintf("%q", line[:min(len(line), len(intro))])
}

// Parse returns the header and a Reader that begins at the start of the
// payload.
func Parse(input io.Reader) (*Header, io.Reader, error) {
	h := &Header{}
	rr := bufio.NewReader(input)
	hr := &headerReader{r: rr}

	line, err := hr.ReadString('\n')
	if err == io.EOF {
		if len(line) == 0 {
			return nil, nil, errorf("file is empty")
		}
		if description := describeIntro(line); description != "" {
			return nil, nil, errorf("unexpected EOF reading intro: %s", description)
		}
		return nil, nil, errorf("unexpected EOF reading intro, expected %q", intro)
	} else if err != nil {
		// headerReader errors are already ParseErrors; don't nest the prefix.
		if _, ok := err.(*ParseError); ok {
			return nil, nil, err
		}
		return nil, nil, errorf("failed to read intro: %w", err)
	}
	if line != intro {
		if description := describeIntro(line); description != "" {
			return nil, nil, errorf("unexpected intro: %s", description)
		}
		return nil, nil, errorf("unexpected intro, expected %q", intro)
	}

	sr := &StanzaReader{r: hr}
	for {
		peek, err := hr.Peek(len(footerPrefix))
		if err != nil {
			// headerReader errors are already ParseErrors; don't nest the prefix.
			if _, ok := err.(*ParseError); ok {
				return nil, nil, err
			}
			return nil, nil, errorf("failed to read header: %w", err)
		}

		if bytes.Equal(peek, footerPrefix) {
			line, err := hr.ReadBytes('\n')
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read header: %w", err)
			}

			prefix, args := splitArgs(line)
			if prefix != string(footerPrefix) || len(args) != 1 {
				return nil, nil, errorf("malformed closing line: %q", line)
			}
			h.MAC, err = DecodeString(args[0])
			if err != nil || len(h.MAC) != 32 {
				return nil, nil, errorf("malformed closing line %q: %v", line, err)
			}
			break
		}
		if len(h.Recipients) == maxRecipientStanzas {
			return nil, nil, errorf("header contains more than %d recipient stanzas", maxRecipientStanzas)
		}

		s, err := sr.ReadStanza()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse header: %w", err)
		}
		h.Recipients = append(h.Recipients, s)
	}
	if len(h.Recipients) == 0 {
		return nil, nil, errorf("no recipient stanzas")
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
	prefix, rest, ok := strings.Cut(l, " ")
	if !ok {
		return l, nil
	}

	var args []string
	for arg := range strings.SplitSeq(rest, " ") {
		if !isValidString(arg) || len(args) > maxStanzaArgs {
			return l, nil
		}
		args = append(args, arg)
	}
	return prefix, args
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
