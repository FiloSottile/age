// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestScryptMinWorkFactor(t *testing.T) {
	const password = "test passphrase"
	plaintext := []byte("minimum work factor test")
	for _, logN := range []int{1, 9, 10, 11} {
		t.Run(fmt.Sprint(logN), func(t *testing.T) {
			r, err := age.NewScryptRecipient(password)
			if err != nil {
				t.Fatal(err)
			}
			r.SetWorkFactor(logN)
			var ciphertext bytes.Buffer
			w, err := age.Encrypt(&ciphertext, r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(plaintext); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			for _, min := range []int{0, 1, 10} {
				t.Run(fmt.Sprintf("min=%d", min), func(t *testing.T) {
					i, err := age.NewScryptIdentity(password)
					if err != nil {
						t.Fatal(err)
					}
					if min != 0 {
						i.SetMinWorkFactor(min)
					}
					out, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), i)
					if logN < min {
						if err == nil || !strings.Contains(err.Error(), "scrypt work factor too small") {
							t.Fatalf("expected low work factor error, got %v", err)
						}
						if errors.Is(err, age.ErrIncorrectIdentity) {
							t.Error("a rejected work factor must not be treated as an incorrect identity")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(out)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, plaintext) {
						t.Fatalf("got %q, want %q", got, plaintext)
					}
				})
			}
		})
	}
}

func TestScryptMinWorkFactorBeforeDecrypt(t *testing.T) {
	i, err := age.NewScryptIdentity("test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	i.SetMinWorkFactor(11)
	// The missing body must not mask the rejected work factor. Keep the
	// work factor low so that a regression cannot exhaust test resources.
	_, err = i.Unwrap([]*age.Stanza{{
		Type: "scrypt",
		Args: []string{"AAAAAAAAAAAAAAAAAAAAAA", "10"},
	}})
	if err == nil || err.Error() != "scrypt work factor too small: 10" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScryptMinWorkFactorLimits(t *testing.T) {
	for _, logN := range []int{-1, 0, 1, 30, 31} {
		t.Run(fmt.Sprint(logN), func(t *testing.T) {
			i, err := age.NewScryptIdentity("test passphrase")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				got := recover()
				if wantPanic := logN < 1 || logN > 30; (got != nil) != wantPanic {
					t.Errorf("panic = %v, want panic = %v", got, wantPanic)
				}
			}()
			i.SetMinWorkFactor(logN)
		})
	}
}

func TestScryptMinAndMaxWorkFactor(t *testing.T) {
	for _, setters := range []string{"min-first", "max-first"} {
		t.Run(setters, func(t *testing.T) {
			i, err := age.NewScryptIdentity("test passphrase")
			if err != nil {
				t.Fatal(err)
			}
			if setters == "min-first" {
				i.SetMinWorkFactor(10)
				i.SetMaxWorkFactor(11)
			} else {
				i.SetMaxWorkFactor(11)
				i.SetMinWorkFactor(10)
			}
			for _, tc := range []struct {
				logN string
				want string
			}{
				{"9", "scrypt work factor too small: 9"},
				{"10", "invalid scrypt recipient block: incorrect file key size"},
				{"11", "invalid scrypt recipient block: incorrect file key size"},
				{"12", "scrypt work factor too large: 12"},
			} {
				_, err := i.Unwrap([]*age.Stanza{{
					Type: "scrypt",
					Args: []string{"AAAAAAAAAAAAAAAAAAAAAA", tc.logN},
				}})
				if err == nil || err.Error() != tc.want {
					t.Errorf("logN=%s: got %v, want %q", tc.logN, err, tc.want)
				}
			}
			// The minimum can be lowered again without changing the maximum.
			i.SetMinWorkFactor(1)
			_, err = i.Unwrap([]*age.Stanza{{
				Type: "scrypt",
				Args: []string{"AAAAAAAAAAAAAAAAAAAAAA", "9"},
			}})
			if err == nil || strings.Contains(err.Error(), "work factor") {
				t.Errorf("lowered minimum unexpectedly rejected the work factor: %v", err)
			}
		})
	}
}
