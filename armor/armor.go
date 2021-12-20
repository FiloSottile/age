// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package armor provides a strict, streaming implementation of the ASCII
// armoring format for age files.
//
// It's PEM with type "AGE ENCRYPTED FILE", 64 character columns, no headers,
// and strict base64 decoding.
package armor

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"

	"filippo.io/age/internal/format"
)

const (
	Header = "-----BEGIN AGE ENCRYPTED FILE-----"
	Footer = "-----END AGE ENCRYPTED FILE-----"
)

type armoredWriter struct {
	started, closed bool
	encoder         *format.WrappedBase64Encoder
	dst             io.Writer
}

func (a *armoredWriter) Write(p []byte) (int, error) {
	if !a.started {
		if _, err := io.WriteString(a.dst, Header+"\n"); err != nil {
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
	footer := Footer + "\n"
	if !a.encoder.LastLineIsEmpty() {
		footer = "\n" + footer
	}
	_, err := io.WriteString(a.dst, footer)
	return err
}

func NewWriter(dst io.Writer) io.WriteCloser {
	// TODO: write a test with aligned and misaligned sizes, and 8 and 10 steps.
	return &armoredWriter{
		dst:     dst,
		encoder: format.NewWrappedBase64Encoder(base64.StdEncoding, dst),
	}
}

type armoredReader struct {
	r       *bufio.Reader
	started bool
	unread  []byte // backed by buf
	buf     [format.BytesPerLine]byte
	err     error
}

func NewReader(r io.Reader) io.Reader {
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
		if string(line) != Header {
			return 0, r.setErr(errors.New("invalid armor first line: " + string(line)))
		}
		r.started = true
	}
	line, err := getLine()
	if err != nil {
		return 0, r.setErr(err)
	}
	if string(line) == Footer {
		return 0, r.setErr(io.EOF)
	}
	if len(line) > format.ColumnsPerLine {
		return 0, r.setErr(errors.New("invalid armor: column limit exceeded"))
	}
	r.unread = r.buf[:]
	n, err := base64.StdEncoding.Strict().Decode(r.unread, line)
	if err != nil {
		return 0, r.setErr(errors.New("invalid armor: " + err.Error()))
	}
	r.unread = r.unread[:n]

	if n < format.BytesPerLine {
		line, err := getLine()
		if err != nil {
			return 0, r.setErr(err)
		}
		if string(line) != Footer {
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
