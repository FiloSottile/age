// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestVectors(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.age")
	for _, f := range files {
		_, name := filepath.Split(f)
		name = strings.TrimSuffix(name, ".age")
		expectFailure := strings.HasPrefix(name, "fail_")
		t.Run(name, func(t *testing.T) {
			var identities []age.Identity
			ids, err := parseIdentitiesFile("testdata/" + name + "_key.txt")
			if err == nil {
				identities = append(identities, ids...)
			}
			password, err := ioutil.ReadFile("testdata/" + name + "_password.txt")
			if err == nil {
				i, err := age.NewScryptIdentity(string(password))
				if err != nil {
					t.Fatal(err)
				}
				identities = append(identities, i)
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

func TestYAML(t *testing.T) {
	tests := []struct {
		Description  string
		Input        string
		Expected     string
		DiscardNoTag bool
	}{
		{
			Description: "Not style defined",
			Input: `password: !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Double quoted",
			Input: `password: !crypto/age:DoubleQuoted |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:DoubleQuoted "ThisIsMyReallyEncryptedPassword"`),
		},
		{
			Description: "Single quoted",
			Input: `password: !crypto/age:SingleQuoted |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:SingleQuoted 'ThisIsMyReallyEncryptedPassword'`),
		},
		{
			Description: "Literal",
			Input: `password: !crypto/age:Literal |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:Literal |-
  ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Folded",
			Input: `password: !crypto/age:Folded |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:Folded >-
  ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Flow",
			Input: `password: !crypto/age:Flow |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: !crypto/age:Flow ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "No tag",
			Input: `password: !crypto/age:NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Double quoted, No Tag",
			Input: `password: !crypto/age:DoubleQuoted,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: "ThisIsMyReallyEncryptedPassword"`),
		},
		{
			Description: "Single quoted, No Tag",
			Input: `password: !crypto/age:SingleQuoted,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: 'ThisIsMyReallyEncryptedPassword'`),
		},
		{
			Description: "Literal, No Tag",
			Input: `password: !crypto/age:Literal,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: |-
  ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Folded, No Tag",
			Input: `password: !crypto/age:Folded,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: >-
  ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Flow, No Tag",
			Input: `password: !crypto/age:Flow,NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----`,
			Expected: fmt.Sprintln(`password: ThisIsMyReallyEncryptedPassword`),
		},
		{
			Description: "Anchor",
			Input: `password: &password !crypto/age |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----
dup: *password`,
			Expected: fmt.Sprintln(`password: &password !crypto/age ThisIsMyReallyEncryptedPassword
dup: *password`),
		},
		{
			Description: "Anchor, No Tag",
			Input: `db_password: &password !crypto/age:NoTag |
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
  OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
  amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
  alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
  gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
  -----END AGE ENCRYPTED FILE-----
dup: *password`,
			Expected: fmt.Sprintln(`db_password: &password ThisIsMyReallyEncryptedPassword
dup: *password`),
		},
		{
			Description: "Comment, Anchor, No Tag",
			Input: `db:
  # this is a head comment
  password: &password !crypto/age:NoTag | # this is a line comment
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
    OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
    amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
    alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
    gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
    -----END AGE ENCRYPTED FILE-----
  # this is a footer comment
dup: *password # alias comment`,
			Expected: fmt.Sprintln(`db:
  # this is a head comment
  password: &password ThisIsMyReallyEncryptedPassword # this is a line comment
  # this is a footer comment
dup: *password # alias comment`),
		},
		{
			Description: "Documents, Comment, Anchor, No Tag",
			Input: `db:
  # this is a head comment
  password: &password !crypto/age | # this is a line comment
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
    OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
    amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
    alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
    gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
    -----END AGE ENCRYPTED FILE-----
  # this is a footer comment
dup: *password # alias comment
---
db:
  # this is a head comment
  password: &password !crypto/age:NoTag | # this is a line comment
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBpTmZNODFnSlAzM0F2TEs0
    OU9iYk54T0tPN2E5OGdvVkZhVGw1anFyVEV3CjlyaE5RUkh6cStLT2V6aFJua0VD
    amlzc3lyS09sVjZKV0FjUjZzMmVTWm8KLS0tIFFHeURlKzB4QW91WE5GZnNNdGdn
    alEvdW5oaGVocUp5bVVTNzlQRmduZmcK66z0fR47miRVT/0t8obsCRfacNgy5T6C
    gLJ+Nu91e/apOC85VBL/rDgbakSmfHPsCo486rDB0N3Ul0qtHT1m
    -----END AGE ENCRYPTED FILE-----
  # this is a footer comment
dup: *password # alias comment`,
			Expected: fmt.Sprintln(`db:
  # this is a head comment
  password: &password !crypto/age ThisIsMyReallyEncryptedPassword # this is a line comment
  # this is a footer comment
dup: *password # alias comment
---
db:
  # this is a head comment
  password: &password ThisIsMyReallyEncryptedPassword # this is a line comment
  # this is a footer comment
dup: *password # alias comment`),
		},
	}

	recFile, err := os.Open("./testdata/yaml.pub")
	if err != nil {
		t.Fatal(err)
	}

	recs, err := age.ParseRecipients(recFile)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		input := test.Input
		for i := 0; i < 2; i++ {
			in := bytes.NewBufferString(input)
			decryptOut := bytes.NewBuffer(nil)
			encryptOut := bytes.NewBuffer(nil)

			// decrypt
			decryptYAML([]string{"./testdata/yaml.key"}, in, decryptOut, test.DiscardNoTag)

			// compare decrypted with expected
			if decryptOut.String() != test.Expected {
				t.Errorf("Test \"%s\" failed:\nExpected:\n%sActual:\n%s", test.Description, test.Expected, decryptOut.String())
			}

			// re-encrypt data for second pass
			encryptYAML(recs, decryptOut, encryptOut)

			// assign encrypted result to test input
			input = encryptOut.String()
		}
	}
}
