// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age/internal/age"
)

func TestVectors(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.age")
	for _, f := range files {
		name := strings.TrimSuffix(strings.TrimPrefix(f, "testdata/"), ".age")
		t.Run(name, func(t *testing.T) {
			identities, err := parseIdentitiesFile("testdata/" + name + "_key.txt")
			if err != nil {
				t.Fatal(err)
			}
			for _, i := range identities {
				t.Logf("%s", i.Type())
			}

			in, err := os.Open("testdata/" + name + ".age")
			if err != nil {
				t.Fatal(err)
			}
			r, err := age.Decrypt(in, identities...)
			if err != nil {
				t.Fatal(err)
			}
			out, err := ioutil.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s", out)
		})
	}
}
