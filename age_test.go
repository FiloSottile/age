// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"filippo.io/age/internal/bech32"
	"filippo.io/age/plugin"
)

func ExampleEncrypt() {
	publicKey := "age1cy0su9fwf3gf9mw868g5yut09p6nytfmmnktexz2ya5uqg9vl9sss4euqm"
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		log.Fatalf("Failed to parse public key %q: %v", publicKey, err)
	}

	out := &bytes.Buffer{}

	w, err := age.Encrypt(out, recipient)
	if err != nil {
		log.Fatalf("Failed to create encrypted file: %v", err)
	}
	if _, err := io.WriteString(w, "Black lives matter."); err != nil {
		log.Fatalf("Failed to write to encrypted file: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Failed to close encrypted file: %v", err)
	}

	fmt.Printf("Encrypted file size: %d\n", out.Len())
	// Output:
	// Encrypted file size: 219
}

// DO NOT hardcode the private key. Store it in a secret storage solution,
// on disk if the local machine is trusted, or have the user provide it.
var privateKey string

func init() {
	privateKey = "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU"
}

func ExampleDecrypt() {
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	f, err := os.Open("testdata/example.age")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	r, err := age.Decrypt(f, identity)
	if err != nil {
		log.Fatalf("Failed to open encrypted file: %v", err)
	}
	out := &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		log.Fatalf("Failed to read encrypted file: %v", err)
	}

	fmt.Printf("File contents: %q\n", out.Bytes())
	// Output:
	// File contents: "Black lives matter."
}

func ExampleParseIdentities() {
	keyFile, err := os.Open("testdata/example_keys.txt")
	if err != nil {
		log.Fatalf("Failed to open private keys file: %v", err)
	}
	identities, err := age.ParseIdentities(keyFile)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	f, err := os.Open("testdata/example.age")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	r, err := age.Decrypt(f, identities...)
	if err != nil {
		log.Fatalf("Failed to open encrypted file: %v", err)
	}
	out := &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		log.Fatalf("Failed to read encrypted file: %v", err)
	}

	fmt.Printf("File contents: %q\n", out.Bytes())
	// Output:
	// File contents: "Black lives matter."
}

func ExampleGenerateX25519Identity() {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	fmt.Printf("Public key: %s...\n", identity.Recipient().String()[:4])
	fmt.Printf("Private key: %s...\n", identity.String()[:16])
	// Output:
	// Public key: age1...
	// Private key: AGE-SECRET-KEY-1...
}

const helloWorld = "Hello, Twitch!"

func TestEncryptDecryptX25519(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, a.Recipient(), b.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, helloWorld); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := age.Decrypt(buf, b)
	if err != nil {
		t.Fatal(err)
	}
	outBytes, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(outBytes) != helloWorld {
		t.Errorf("wrong data: %q, excepted %q", outBytes, helloWorld)
	}
}

func TestEncryptDecryptScrypt(t *testing.T) {
	password := "twitch.tv/filosottile"

	r, err := age.NewScryptRecipient(password)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(15)
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, helloWorld); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	i, err := age.NewScryptIdentity(password)
	if err != nil {
		t.Fatal(err)
	}
	out, err := age.Decrypt(buf, i)
	if err != nil {
		t.Fatal(err)
	}
	outBytes, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(outBytes) != helloWorld {
		t.Errorf("wrong data: %q, excepted %q", outBytes, helloWorld)
	}
}

func ExampleDecryptReaderAt() {
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	f, err := os.Open("testdata/example.zip.age")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	stat, err := f.Stat()
	if err != nil {
		log.Fatalf("Failed to stat file: %v", err)
	}

	r, size, err := age.DecryptReaderAt(f, stat.Size(), identity)
	if err != nil {
		log.Fatalf("Failed to open encrypted file: %v", err)
	}

	z, err := zip.NewReader(r, size)
	if err != nil {
		log.Fatalf("Failed to open zip: %v", err)
	}
	contents, err := fs.ReadFile(z, "example.txt")
	if err != nil {
		log.Fatalf("Failed to read file from zip: %v", err)
	}

	fmt.Printf("File contents: %q\n", contents)
	// Output:
	// File contents: "Black lives matter."
}

func TestParseIdentities(t *testing.T) {
	tests := []struct {
		name      string
		wantCount int
		wantErr   bool
		file      string
	}{
		{"valid", 2, false, `
# this is a comment
# AGE-SECRET-KEY-1705XN76M8EYQ8M9PY4E2G3KA8DN7NSCGT3V4HMN20H3GCX4AS6HSSTG8D3
#

AGE-SECRET-KEY-1D6K0SGAX3NU66R4GYFZY0UQWCLM3UUSF3CXLW4KXZM342WQSJ82QKU59QJ
AGE-SECRET-KEY-19WUMFE89H3928FRJ5U3JYRNHM6CERQGKSQ584AQ8QY7T7R09D32SWE4DYH`},
		{"invalid", 0, true, `
AGE-SECRET-KEY-1705XN76M8EYQ8M9PY4E2G3KA8DN7NSCGT3V4HMN20H3GCX4AS6HSSTG8D3
AGE-SECRET-KEY--1D6K0SGAX3NU66R4GYFZY0UQWCLM3UUSF3CXLW4KXZM342WQSJ82QKU59Q`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := age.ParseIdentities(strings.NewReader(tt.file))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIdentities() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantCount {
				t.Errorf("ParseIdentities() returned %d identities, want %d", len(got), tt.wantCount)
			}
		})
	}
}

func TestParseErrorsDoNotIncludeLine(t *testing.T) {
	x25519, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// Re-encode the hybrid identity as a plugin identity.
	_, seed, err := bech32.Decode(hybrid.String())
	if err != nil {
		t.Fatal(err)
	}
	pluginIdentity, err := bech32.Encode("AGE-PLUGIN-PQ-", seed)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		line  string
		parse func(io.Reader) error
	}{
		{"identities/plugin", pluginIdentity, func(r io.Reader) error {
			_, err := age.ParseIdentities(r)
			return err
		}},
		{"recipients/x25519", x25519.String(), func(r io.Reader) error {
			_, err := age.ParseRecipients(r)
			return err
		}},
		{"recipients/hybrid", hybrid.String(), func(r io.Reader) error {
			_, err := age.ParseRecipients(r)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.parse(strings.NewReader("# a comment\n" + tt.line + "\n"))
			if err == nil {
				t.Fatal("expected an error for an unrecognized line, got nil")
			}
			if strings.Contains(err.Error(), tt.line) {
				t.Errorf("error includes the private key from the file: %v", err)
			}
			if !strings.Contains(err.Error(), "line 2") {
				t.Errorf("error doesn't say which line failed: %v", err)
			}
		})
	}
}

func paddedFile(pad int, lines string) io.Reader {
	const chunkSize = 1 << 16
	chunk := strings.Repeat("#\n", chunkSize/2)
	var readers []io.Reader
	if pad%2 != 0 {
		readers = append(readers, strings.NewReader("\n"))
		pad--
	}
	for ; pad > chunkSize; pad -= chunkSize {
		readers = append(readers, strings.NewReader(chunk))
	}
	return io.MultiReader(append(readers,
		strings.NewReader(chunk[:pad]), strings.NewReader(lines))...)
}

func TestParseFileSizeLimit(t *testing.T) {
	const sizeLimit = 1 << 24
	const identity = "AGE-SECRET-KEY-1D6K0SGAX3NU66R4GYFZY0UQWCLM3UUSF3CXLW4KXZM342WQSJ82QKU59QJ\n"
	const recipient = "age1cy0su9fwf3gf9mw868g5yut09p6nytfmmnktexz2ya5uqg9vl9sss4euqm\n"
	tests := []struct {
		name  string
		entry string
		parse func(io.Reader) (int, error)
	}{
		{"identities", identity, func(r io.Reader) (int, error) {
			ids, err := age.ParseIdentities(r)
			return len(ids), err
		}},
		{"recipients", recipient, func(r io.Reader) (int, error) {
			recipients, err := age.ParseRecipients(r)
			return len(recipients), err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/at limit", func(t *testing.T) {
			r := paddedFile(sizeLimit-4*len(tt.entry), strings.Repeat(tt.entry, 4))
			n, err := tt.parse(r)
			if err != nil {
				t.Fatal(err)
			}
			if n != 4 {
				t.Errorf("got %d entries, want 4", n)
			}
		})
		t.Run(tt.name+"/over limit", func(t *testing.T) {
			r := paddedFile(sizeLimit-4*len(tt.entry), strings.Repeat(tt.entry, 8))
			if _, err := tt.parse(r); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

type testRecipient struct {
	labels []string
}

func (testRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	panic("expected WrapWithLabels instead")
}

func (t testRecipient) WrapWithLabels(fileKey []byte) (s []*age.Stanza, labels []string, err error) {
	return []*age.Stanza{{Type: "test"}}, t.labels, nil
}

type emptyRecipient struct{}

func (emptyRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	return nil, nil
}

func TestEmptyRecipient(t *testing.T) {
	buf := &bytes.Buffer{}
	if _, err := age.Encrypt(buf, emptyRecipient{}); err == nil {
		t.Fatal("Encrypt accepted a recipient with no stanzas")
	}
	if buf.Len() != 0 {
		t.Errorf("Encrypt wrote %d bytes", buf.Len())
	}
}

func TestLabels(t *testing.T) {
	scrypt, err := age.NewScryptRecipient("xxx")
	if err != nil {
		t.Fatal(err)
	}
	i, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	x25519 := i.Recipient()
	pqc := testRecipient{[]string{"postquantum"}}
	pqcAndFoo := testRecipient{[]string{"postquantum", "foo"}}
	fooAndPQC := testRecipient{[]string{"foo", "postquantum"}}

	if _, err := age.Encrypt(io.Discard, scrypt, scrypt); err == nil {
		t.Error("expected two scrypt recipients to fail")
	}
	if _, err := age.Encrypt(io.Discard, scrypt, x25519); err == nil {
		t.Error("expected x25519 mixed with scrypt to fail")
	}
	if _, err := age.Encrypt(io.Discard, x25519, scrypt); err == nil {
		t.Error("expected x25519 mixed with scrypt to fail")
	}
	if _, err := age.Encrypt(io.Discard, pqc, x25519); err == nil {
		t.Error("expected x25519 mixed with pqc to fail")
	}
	if _, err := age.Encrypt(io.Discard, x25519, pqc); err == nil {
		t.Error("expected x25519 mixed with pqc to fail")
	}
	if _, err := age.Encrypt(io.Discard, pqc, pqc); err != nil {
		t.Errorf("expected two pqc to work, got %v", err)
	}
	if _, err := age.Encrypt(io.Discard, pqc); err != nil {
		t.Errorf("expected one pqc to work, got %v", err)
	}
	if _, err := age.Encrypt(io.Discard, pqcAndFoo, pqc); err == nil {
		t.Error("expected pqc+foo mixed with pqc to fail")
	}
	if _, err := age.Encrypt(io.Discard, pqc, pqcAndFoo); err == nil {
		t.Error("expected pqc+foo mixed with pqc to fail")
	}
	if _, err := age.Encrypt(io.Discard, pqc, pqc, pqcAndFoo); err == nil {
		t.Error("expected pqc+foo mixed with pqc to fail")
	}
	if _, err := age.Encrypt(io.Discard, pqcAndFoo, pqcAndFoo); err != nil {
		t.Errorf("expected two pqc+foo to work, got %v", err)
	}
	if _, err := age.Encrypt(io.Discard, pqcAndFoo, fooAndPQC); err != nil {
		t.Errorf("expected pqc+foo mixed with foo+pqc to work, got %v", err)
	}
}

// testIdentity is a non-native identity that records if Unwrap is called.
type testIdentity struct {
	called bool
}

func (ti *testIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	ti.called = true
	return nil, age.ErrIncorrectIdentity
}

type noMatchIdentity int

func (noMatchIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	return nil, age.ErrIncorrectIdentity
}

func TestDecryptDoesNotReorderIdentities(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	encrypted := buf.Bytes()
	header, err := age.ExtractHeader(bytes.NewReader(encrypted))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		decrypt func([]age.Identity) error
	}{
		{"Decrypt", func(identities []age.Identity) error {
			_, err := age.Decrypt(bytes.NewReader(encrypted), identities...)
			return err
		}},
		{"DecryptReaderAt", func(identities []age.Identity) error {
			_, _, err := age.DecryptReaderAt(bytes.NewReader(encrypted), int64(len(encrypted)), identities...)
			return err
		}},
		{"DecryptHeader", func(identities []age.Identity) error {
			_, err := age.DecryptHeader(header, identities...)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identities := []age.Identity{noMatchIdentity(1), identity, noMatchIdentity(2)}
			want := slices.Clone(identities)
			if err := tt.decrypt(identities); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(identities, want) {
				t.Error("identities were reordered")
			}
		})
	}

	t.Run("concurrent", func(t *testing.T) {
		identities := []age.Identity{noMatchIdentity(1), identity, noMatchIdentity(2)}
		want := slices.Clone(identities)
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				for range 20 {
					if _, err := age.Decrypt(bytes.NewReader(encrypted), identities...); err != nil {
						t.Error(err)
					}
				}
			})
		}
		wg.Wait()
		if !slices.Equal(identities, want) {
			t.Error("identities were reordered")
		}
	})
}

func TestDecryptNativeIdentitiesFirst(t *testing.T) {
	correct, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, correct.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	nonNative := &testIdentity{}

	// Pass identities: unrelated native, non-native, correct native.
	// Native identities should be tried first, so correct should match
	// before nonNative is ever called.
	_, err = age.Decrypt(bytes.NewReader(buf.Bytes()), unrelated, nonNative, correct)
	if err != nil {
		t.Fatal(err)
	}

	if nonNative.called {
		t.Error("non-native identity was called, but native identities should be tried first")
	}
}

type stanzaTypeRecipient string

func (s stanzaTypeRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: string(s)}}, nil
}

func TestNoIdentityMatchErrorStanzaTypes(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, a.Recipient(), stanzaTypeRecipient("other"), b.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, helloWorld); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = age.Decrypt(bytes.NewReader(buf.Bytes()), wrong)
	if err == nil {
		t.Fatal("expected decryption to fail")
	}

	var noMatch *age.NoIdentityMatchError
	if !errors.As(err, &noMatch) {
		t.Fatalf("expected NoIdentityMatchError, got %T: %v", err, err)
	}

	want := []string{"X25519", "other", "X25519"}
	if !slices.Equal(noMatch.StanzaTypes, want) {
		t.Errorf("StanzaTypes = %v, want %v", noMatch.StanzaTypes, want)
	}
}

func TestScryptIdentityErrors(t *testing.T) {
	t.Run("not passphrase-encrypted", func(t *testing.T) {
		i, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}

		buf := &bytes.Buffer{}
		w, err := age.Encrypt(buf, i.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		scryptID, err := age.NewScryptIdentity("password")
		if err != nil {
			t.Fatal(err)
		}
		_, err = age.Decrypt(bytes.NewReader(buf.Bytes()), scryptID)
		if err == nil {
			t.Fatal("expected decryption to fail")
		}
		if !errors.Is(err, age.ErrIncorrectIdentity) {
			t.Errorf("expected ErrIncorrectIdentity, got %v", err)
		}
		if !strings.Contains(err.Error(), "not passphrase-encrypted") {
			t.Errorf("expected error to mention 'not passphrase-encrypted', got %v", err)
		}
	})

	t.Run("incorrect passphrase", func(t *testing.T) {
		r, err := age.NewScryptRecipient("correct-password")
		if err != nil {
			t.Fatal(err)
		}
		r.SetWorkFactor(10) // Low for fast test

		buf := &bytes.Buffer{}
		w, err := age.Encrypt(buf, r)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		scryptID, err := age.NewScryptIdentity("wrong-password")
		if err != nil {
			t.Fatal(err)
		}
		_, err = age.Decrypt(bytes.NewReader(buf.Bytes()), scryptID)
		if err == nil {
			t.Fatal("expected decryption to fail")
		}
		if !errors.Is(err, age.ErrIncorrectIdentity) {
			t.Errorf("expected ErrIncorrectIdentity, got %v", err)
		}
		if !strings.Contains(err.Error(), "incorrect passphrase") {
			t.Errorf("expected error to mention 'incorrect passphrase', got %v", err)
		}
	})
}

func TestDetachedHeader(t *testing.T) {
	i, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, i.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, helloWorld); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	encrypted := buf.Bytes()

	header, err := age.ExtractHeader(bytes.NewReader(encrypted))
	if err != nil {
		t.Fatal(err)
	}

	fileKey, err := age.DecryptHeader(header, i)
	if err != nil {
		t.Fatal(err)
	}

	identity := age.NewInjectedFileKeyIdentity(fileKey)
	out, err := age.Decrypt(bytes.NewReader(encrypted), identity)
	if err != nil {
		t.Fatal(err)
	}
	outBytes, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(outBytes) != helloWorld {
		t.Errorf("wrong data: %q, expected %q", outBytes, helloWorld)
	}
}

func TestEncryptReader(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.EncryptReader(strings.NewReader(helloWorld), a.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	if _, err := io.Copy(buf, r); err != nil {
		t.Fatal(err)
	}

	out, err := age.Decrypt(buf, a)
	if err != nil {
		t.Fatal(err)
	}
	outBytes, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(outBytes) != helloWorld {
		t.Errorf("wrong data: %q, excepted %q", outBytes, helloWorld)
	}
}

func TestParseUnicode(t *testing.T) {
	// U+212A folds to "k", shrinking the data part below the checksum.
	w := "AA3100AC" + string(rune(0x212A))
	for _, tc := range []struct {
		name string
		fn   func(string) error
	}{
		{"age.ParseX25519Recipient", func(s string) error { _, err := age.ParseX25519Recipient(s); return err }},
		{"age.ParseX25519Identity", func(s string) error { _, err := age.ParseX25519Identity(s); return err }},
		{"age.ParseHybridRecipient", func(s string) error { _, err := age.ParseHybridRecipient(s); return err }},
		{"age.ParseHybridIdentity", func(s string) error { _, err := age.ParseHybridIdentity(s); return err }},
		{"plugin.ParseIdentity", func(s string) error { _, _, err := plugin.ParseIdentity(s); return err }},
		{"plugin.ParseRecipient", func(s string) error { _, _, err := plugin.ParseRecipient(s); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panicked on malformed input: %v", tc.name, r)
				}
			}()
			if err := tc.fn(w); err == nil {
				t.Errorf("%s returned nil error, want error", tc.name)
			}
		})
	}
}
