// Copyright 2021 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package format_test

import (
	"bytes"
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
