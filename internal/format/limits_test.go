// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package format

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestStanzaReaderRejectsOversizedStanza(t *testing.T) {
	var input bytes.Buffer
	input.WriteString("-> test ")
	input.WriteString(strings.Repeat("a", MaxStanzaSize))
	input.WriteString("\n\n")

	sr := NewStanzaReader(bufio.NewReader(&input))
	if _, err := sr.ReadStanza(); err == nil {
		t.Fatal("ReadStanza accepted an oversized stanza")
	} else if !strings.Contains(err.Error(), "stanza exceeds") {
		t.Fatalf("ReadStanza error = %v, want stanza size limit error", err)
	}
}

func TestParseRejectsOversizedHeader(t *testing.T) {
	var input bytes.Buffer
	input.WriteString(intro)
	for input.Len() <= MaxHeaderSize {
		input.WriteString("-> test ")
		input.WriteString(strings.Repeat("a", MaxStanzaSize-1024))
		input.WriteString("\n\n")
	}
	input.WriteString("--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")

	if _, _, err := Parse(&input); err == nil {
		t.Fatal("Parse accepted an oversized header")
	} else if !strings.Contains(err.Error(), "header exceeds") {
		t.Fatalf("Parse error = %v, want header size limit error", err)
	}
}
