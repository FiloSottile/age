// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package format

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
)

type newlineWriter struct {
	dst     io.Writer
	written int
}

func (w *newlineWriter) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		remainingInLine := columnsPerLine - (w.written % columnsPerLine)
		if remainingInLine == columnsPerLine && w.written != 0 {
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

type CloserFunc func() error

func (f CloserFunc) Close() error { return f() }

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }

func NopCloser(w io.Writer) io.WriteCloser { return nopCloser{w} }

const armorPreamble = "-----BEGIN AGE ENCRYPTED FILE-----"
const armorEnd = "-----END AGE ENCRYPTED FILE-----"

type armoredWriter struct {
	started, closed bool
	encoder         io.WriteCloser
	dst             io.Writer
}

func (a *armoredWriter) Write(p []byte) (int, error) {
	if !a.started {
		if _, err := io.WriteString(a.dst, armorPreamble+"\n"); err != nil {
			return 0, err
		}
	}
	a.started = true
	return a.encoder.Write(p)
}

func (a *armoredWriter) Close() error {
	if a.closed {
		return errors.New("ArmoredWriter already closed")
	}
	a.closed = true
	if err := a.encoder.Close(); err != nil {
		return err
	}
	_, err := io.WriteString(a.dst, "\n"+armorEnd+"\n")
	return err
}

func ArmoredWriter(dst io.Writer) io.WriteCloser {
	// TODO: write a test with aligned and misaligned sizes, and 8 and 10 steps.
	return &armoredWriter{dst: dst,
		encoder: base64.NewEncoder(base64.StdEncoding.Strict(),
			&newlineWriter{dst: dst})}
}

type armoredReader struct {
	r       *bufio.Reader
	started bool
	unread  []byte // backed by buf
	buf     [bytesPerLine]byte
	err     error
}

func ArmoredReader(r io.Reader) io.Reader {
	return &armoredReader{r: bufio.NewReader(r)}
}

func (r *armoredReader) Read(p []byte) (int, error) {
	if len(r.unread) > 0 {
		n := copy(p, r.unread)
		r.unread = r.unread[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}

	getLine := func() ([]byte, error) {
		line, err := r.r.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			if err == io.EOF {
				err = errors.New("invalid armor: unexpected EOF")
			}
			return nil, err
		}
		return bytes.TrimSpace(line), nil
	}

	if !r.started {
		line, err := getLine()
		if err != nil {
			return 0, r.setErr(err)
		}
		if string(line) != armorPreamble {
			return 0, r.setErr(errors.New("invalid armor first line: " + string(line)))
		}
		r.started = true
	}
	line, err := getLine()
	if err != nil {
		return 0, r.setErr(err)
	}
	if string(line) == armorEnd {
		return 0, r.setErr(io.EOF)
	}
	if len(line) > columnsPerLine {
		return 0, r.setErr(errors.New("invalid armor: column limit exceeded"))
	}
	r.unread = r.buf[:]
	n, err := base64.StdEncoding.Strict().Decode(r.unread, line)
	if err != nil {
		return 0, r.setErr(errors.New("invalid armor: " + err.Error()))
	}
	r.unread = r.unread[:n]

	if n < bytesPerLine {
		line, err := getLine()
		if err != nil {
			return 0, r.setErr(err)
		}
		if string(line) != armorEnd {
			return 0, r.setErr(errors.New("invalid armor closing line: " + string(line)))
		}
		r.err = io.EOF
	}

	nn := copy(p, r.unread)
	r.unread = r.unread[nn:]
	return nn, nil
}

func (r *armoredReader) setErr(err error) error {
	r.err = err
	return err
}
