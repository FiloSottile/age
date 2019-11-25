// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package format

import "io"

import "encoding/base64"

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
			_, err := dst.Write([]byte("\n--- end of file ---\n"))
			return err
		}),
	}
}
