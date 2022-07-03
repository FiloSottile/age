// Copyright 2021 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package format_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age/internal/format"
)

func TestStanzaMarshal(t *testing.T) {
	s := &format.Stanza{
		Type: "test",
		Args: []string{"1", "2", "3"},
		Body: nil, // empty
	}
	buf := &bytes.Buffer{}
	s.Marshal(buf)
	if exp := "-> test 1 2 3\n\n"; buf.String() != exp {
		t.Errorf("wrong empty stanza encoding: expected %q, got %q", exp, buf.String())
	}

	buf.Reset()
	s.Body = []byte("AAA")
	s.Marshal(buf)
	if exp := "-> test 1 2 3\nQUFB\n"; buf.String() != exp {
		t.Errorf("wrong normal stanza encoding: expected %q, got %q", exp, buf.String())
	}

	buf.Reset()
	s.Body = bytes.Repeat([]byte("A"), format.BytesPerLine)
	s.Marshal(buf)
	if exp := "-> test 1 2 3\nQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n\n"; buf.String() != exp {
		t.Errorf("wrong 64 columns stanza encoding: expected %q, got %q", exp, buf.String())
	}
}

func FuzzMalleability(f *testing.F) {
	tests, err := filepath.Glob("../../testdata/testkit/*")
	if err != nil {
		f.Fatal(err)
	}
	for _, test := range tests {
		contents, err := os.ReadFile(test)
		if err != nil {
			f.Fatal(err)
		}
		_, contents, ok := bytes.Cut(contents, []byte("\n\n"))
		if !ok {
			f.Fatal("testkit file without header")
		}
		f.Add(contents)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, payload, err := format.Parse(bytes.NewReader(data))
		if err != nil {
			if h != nil {
				t.Error("h != nil on error")
			}
			if payload != nil {
				t.Error("payload != nil on error")
			}
			t.Skip()
		}
		w := &bytes.Buffer{}
		if err := h.Marshal(w); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(w.Bytes(), data) {
			t.Error("Marshal output different from input")
		}
	})
}
