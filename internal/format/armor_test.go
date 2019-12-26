// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package format_test

import (
	"bytes"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"filippo.io/age/internal/format"
)

func TestArmor(t *testing.T) {
	buf := &bytes.Buffer{}
	w := format.ArmoredWriter(buf)
	plain := make([]byte, 611)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		t.Fatal("PEM decoding failed")
	}
	if !bytes.Equal(block.Bytes, plain) {
		t.Error("PEM decoded value doesn't match")
	}

	r := format.ArmoredReader(buf)
	out, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Error("decoded value doesn't match")
	}
}
