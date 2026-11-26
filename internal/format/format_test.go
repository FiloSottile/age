// Copyright 2021 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18

package format_test

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"

	agetest "c2sp.org/CCTV/age"
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

	for _, s := range []*format.Stanza{
		{Type: ""},
		{Type: "test", Args: []string{""}},
		{Type: "test", Args: []string{"a b"}},
		{Type: "test", Args: []string{"a\nb"}},
		{Type: "test", Args: []string{"café"}},
	} {
		buf.Reset()
		if err := s.Marshal(buf); err == nil {
			t.Errorf("Marshal accepted type %q, args %q", s.Type, s.Args)
		}
		if buf.Len() != 0 {
			t.Errorf("Marshal wrote %d bytes", buf.Len())
		}
	}
}

func TestHeaderMarshalNoStanzas(t *testing.T) {
	buf := &bytes.Buffer{}
	if err := (&format.Header{}).Marshal(buf); err == nil {
		t.Fatal("Marshal accepted a header with no stanzas")
	}
	if buf.Len() != 0 {
		t.Errorf("Marshal wrote %d bytes", buf.Len())
	}
}

func TestParseLimits(t *testing.T) {
	const (
		intro          = "age-encryption.org/v1\n"
		maxHeaderBytes = 2 << 20
	)
	footer := "--- " + format.EncodeToString(make([]byte, 32)) + "\n"

	t.Run("header size", func(t *testing.T) {
		makeHeader := func(size int) []byte {
			const opening = "-> test "
			fixed := len(intro) + len(opening) + len("\n\n") + len(footer)
			return []byte(intro + opening + strings.Repeat("a", size-fixed) + "\n\n" + footer)
		}

		if _, _, err := format.Parse(bytes.NewReader(makeHeader(maxHeaderBytes))); err != nil {
			t.Fatalf("maximum-size header was rejected: %v", err)
		}
		_, _, err := format.Parse(bytes.NewReader(makeHeader(maxHeaderBytes + 1)))
		if err == nil || !strings.Contains(err.Error(), "header exceeds 2 MiB") {
			t.Fatalf("unexpected oversized-header error: %v", err)
		}
		var parseError *format.ParseError
		if !errors.As(err, &parseError) {
			t.Errorf("oversized-header error is not a ParseError: %T", err)
		}
		if strings.Count(err.Error(), "parsing age header") != 1 {
			t.Errorf("oversized-header error nests ParseError prefixes: %v", err)
		}

		// An intro line that exceeds the limit before any newline.
		_, _, err = format.Parse(bytes.NewReader(bytes.Repeat([]byte{'a'}, maxHeaderBytes+1)))
		if err == nil || !strings.Contains(err.Error(), "header exceeds 2 MiB") {
			t.Fatalf("unexpected oversized-intro error: %v", err)
		}
		if !errors.As(err, &parseError) {
			t.Errorf("oversized-intro error is not a ParseError: %T", err)
		}
		if strings.Count(err.Error(), "parsing age header") != 1 {
			t.Errorf("oversized-intro error nests ParseError prefixes: %v", err)
		}
	})

	t.Run("recipient stanzas", func(t *testing.T) {
		makeHeader := func(stanzas int) []byte {
			return []byte(intro + strings.Repeat("-> test\n\n", stanzas) + footer)
		}

		if _, _, err := format.Parse(bytes.NewReader(makeHeader(0))); err == nil || !strings.Contains(err.Error(), "no recipient stanzas") {
			t.Fatalf("unexpected zero-stanza error: %v", err)
		}
		if _, _, err := format.Parse(bytes.NewReader(makeHeader(1024))); err != nil {
			t.Fatalf("header with 1024 stanzas was rejected: %v", err)
		}
		_, _, err := format.Parse(bytes.NewReader(makeHeader(1025)))
		if err == nil || !strings.Contains(err.Error(), "more than 1024 recipient stanzas") {
			t.Fatalf("unexpected stanza-limit error: %v", err)
		}
	})

	t.Run("recipient stanza arguments", func(t *testing.T) {
		makeHeader := func(args int) []byte {
			return []byte(intro + "-> test" + strings.Repeat(" a", args) + "\n\n" + footer)
		}

		if _, _, err := format.Parse(bytes.NewReader(makeHeader(128))); err != nil {
			t.Fatalf("stanza with 128 arguments was rejected: %v", err)
		}
		_, _, err := format.Parse(bytes.NewReader(makeHeader(129)))
		if err == nil {
			t.Fatal("stanza with 129 arguments was accepted")
		}
	})

	t.Run("payload is not limited", func(t *testing.T) {
		header := []byte(intro + "-> test\n\n" + footer)
		want := bytes.Repeat([]byte("p"), maxHeaderBytes+1)
		_, payload, err := format.Parse(io.MultiReader(bytes.NewReader(header), bytes.NewReader(want)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(payload)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Error("payload was truncated or modified")
		}
	})

	t.Run("bufio reader is preserved", func(t *testing.T) {
		header := []byte(intro + "-> test\n\n" + footer)
		input := bufio.NewReader(bytes.NewReader(append(header, "payload"...)))
		_, payload, err := format.Parse(input)
		if err != nil {
			t.Fatal(err)
		}
		if payload != input {
			t.Error("Parse did not return the input bufio.Reader")
		}
	})
}

func FuzzMalleability(f *testing.F) {
	tests, err := fs.ReadDir(agetest.Vectors, ".")
	if err != nil {
		f.Fatal(err)
	}
	for _, test := range tests {
		contents, err := fs.ReadFile(agetest.Vectors, test.Name())
		if err != nil {
			f.Fatal(err)
		}
		_, contents, ok := bytes.Cut(contents, []byte("\n\n"))
		if !ok {
			f.Fatal("testkit file without header")
		}
		f.Add(contents)
	}
	if len(tests) == 0 {
		f.Fatal("no test vectors")
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

const secret = "AGE-SECRET-KEY-1NOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTA"

const pluginSecret = "AGE-PLUGIN-PQ-1NOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTA"

func TestParseIntroErrorIsNotSecret(t *testing.T) {
	for _, test := range []struct {
		name   string
		input  string
		secret bool
	}{
		{"identity", secret + "\n", true},
		{"identity, no newline", secret, true},
		{"plugin identity", pluginSecret + "\n", true},
		{"plugin identity, no newline", pluginSecret, true},
		{"truncated intro", "age-encryption.org/v1", false},
		{"binary", "\x00\x01\x02", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := format.Parse(strings.NewReader(test.input))
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), "file is empty") {
				t.Errorf("error says the file is empty, but it is %d bytes: %v",
					len(test.input), err)
			}
			// Check substrings, not just the key prefix.
			if test.secret {
				key := strings.TrimSuffix(test.input, "\n")
				for i := 0; i+17 <= len(key); i++ {
					if strings.Contains(err.Error(), key[i:i+17]) {
						t.Errorf("error includes %q, a run of the first line, "+
							"which is a private key: %v", key[i:i+17], err)
						break
					}
				}
			}
		})
	}

	// Preserve the error for empty files (#416).
	t.Run("empty", func(t *testing.T) {
		_, _, err := format.Parse(strings.NewReader(""))
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "file is empty") {
			t.Errorf("expected an empty file error, got: %v", err)
		}
	})
}

func TestParseIntroErrorShowsMangling(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  string
	}{
		{"crlf", "age-encryption.org/v1\r\n", `\r`},
		{"utf8 bom", "\xef\xbb\xbfage-encryption.org/v1\n", `\ufeff`},
		{"utf16be", "\x00a\x00g\x00e\x00-\x00e\x00n\x00c\x00r\x00y\x00p\x00", `\x00a\x00g\x00e`},
		{"trailing space", "age-encryption.org/v1 \n", `v1 `},
		{"wrong version", "age-encryption.org/v2\n", "v2"},
		{"leading blank line", "\nage-encryption.org/v1\n", `"\n"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := format.Parse(strings.NewReader(test.input))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error does not show the mangling: got %v, want it to contain %q",
					err, test.want)
			}
		})
	}
}

func TestMarshalStanzaLimit(t *testing.T) {
	h := &format.Header{}
	for i := 0; i < 1025; i++ {
		h.Recipients = append(h.Recipients, &format.Stanza{Type: "test"})
	}
	buf := new(bytes.Buffer)
	err := h.Marshal(buf)
	if err == nil || !strings.Contains(err.Error(), "too many recipient stanzas") {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("Marshal wrote %d bytes before failing", buf.Len())
	}
}
