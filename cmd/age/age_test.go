// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestVectors(t *testing.T) {
	defaultIDs, err := parseIdentitiesFile("testdata/default_key.txt")
	if err != nil {
		t.Fatal(err)
	}
	password, err := ioutil.ReadFile("testdata/default_password.txt")
	if err == nil {
		p := strings.TrimSpace(string(password))
		i, err := age.NewScryptIdentity(p)
		if err != nil {
			t.Fatal(err)
		}
		defaultIDs = append(defaultIDs, i)
	}

	files, _ := filepath.Glob("testdata/*.age")
	for _, f := range files {
		_, name := filepath.Split(f)
		name = strings.TrimSuffix(name, ".age")
		expectFailure := strings.HasPrefix(name, "fail_")
		expectNoMatch := strings.HasPrefix(name, "nomatch_")
		t.Run(name, func(t *testing.T) {
			identities := defaultIDs
			ids, err := parseIdentitiesFile("testdata/" + name + "_key.txt")
			if err == nil {
				identities = ids
			}
			password, err := ioutil.ReadFile("testdata/" + name + "_password.txt")
			if err == nil {
				p := strings.TrimSpace(string(password))
				i, err := age.NewScryptIdentity(p)
				if err != nil {
					t.Fatal(err)
				}
				identities = []age.Identity{i}
			}

			in, err := os.Open("testdata/" + name + ".age")
			if err != nil {
				t.Fatal(err)
			}
			r, err := age.Decrypt(in, identities...)
			if expectFailure {
				if err == nil {
					t.Fatal("expected Decrypt failure")
				}
				if e := (&age.NoIdentityMatchError{}); errors.As(err, &e) {
					t.Errorf("got ErrIncorrectIdentity, expected more specific error")
				}
			} else if expectNoMatch {
				if err == nil {
					t.Fatal("expected Decrypt failure")
				}
				if e := (&age.NoIdentityMatchError{}); !errors.As(err, &e) {
					t.Errorf("expected ErrIncorrectIdentity, got %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				out, err := ioutil.ReadAll(r)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("%s", out)
			}
		})
	}
}
