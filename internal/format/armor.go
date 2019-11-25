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

var endOfArmor = []byte("--- end of file ---\n")

func ArmoredWriter(dst io.Writer) io.WriteCloser {
	// TODO: write a test with aligned and misaligned sizes, and 8 and 10 steps.
	w := base64.NewEncoder(b64, &newlineWriter{dst: dst})
	return struct {
		io.Writer
		io.Closer
	}{
		Writer: w,
		Closer: CloserFunc(func() error {
			if err := w.Close(); err != nil {
				return err
			}
			if _, err := dst.Write([]byte("\n")); err != nil {
				return err
			}
			_, err := dst.Write(endOfArmor)
			return err
		}),
	}
}

type armoredReader struct {
	r      *bufio.Reader
	unread []byte // backed by buf
	buf    [bytesPerLine]byte
	err    error
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
		if err != nil {
			if err == io.EOF {
				err = errors.New("invalid input")
			}
			return nil, err
		}
		// Unconditionally accept CRLF because the line ending context of the
		// header is lost at the ArmoredReader caller. =(
		if bytes.HasSuffix(line, []byte("\r\n")) {
			line[len(line)-2] = '\n'
			line = line[:len(line)-1]
		}
		return line, nil
	}

	line, err := getLine()
	if err != nil {
		return 0, r.setErr(err)
	}
	if bytes.Equal(line, endOfArmor) {
		return 0, r.setErr(io.EOF)
	}
	line = bytes.TrimSuffix(line, []byte("\n"))
	if bytes.Contains(line, []byte("\r")) {
		return 0, r.setErr(errors.New("invalid input"))
	}
	if len(line) > columnsPerLine {
		return 0, r.setErr(errors.New("invalid input"))
	}
	r.unread = r.buf[:]
	n, err := b64.Decode(r.unread, line)
	if err != nil {
		return 0, r.setErr(err)
	}
	r.unread = r.unread[:n]

	if n < bytesPerLine {
		line, err := getLine()
		if err != nil {
			return 0, r.setErr(err)
		}
		if !bytes.Equal(line, endOfArmor) {
			return 0, r.setErr(errors.New("invalid input"))
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
