// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// +build gofuzz

package format

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/sergi/go-diff/diffmatchpatch"
)

func Fuzz(data []byte) int {
	isArmored := bytes.HasPrefix(data, []byte("-----BEGIN AGE ENCRYPTED FILE-----"))
	h, payload, err := Parse(bytes.NewReader(data))
	if err != nil {
		if h != nil {
			panic("h != nil on error")
		}
		if payload != nil {
			panic("payload != nil on error")
		}
		return 0
	}
	w := &bytes.Buffer{}
	if isArmored {
		w := ArmoredWriter(w)
		if err := h.Marshal(w); err != nil {
			panic(err)
		}
		if _, err := io.Copy(w, payload); err != nil {
			if strings.Contains(err.Error(), "invalid armor") {
				return 0
			}
			panic(err)
		}
		w.Close()
	} else {
		if err := h.Marshal(w); err != nil {
			panic(err)
		}
		if _, err := io.Copy(w, payload); err != nil {
			panic(err)
		}
	}
	if !bytes.Equal(w.Bytes(), data) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(data), string(w.Bytes()), false)
		fmt.Println(dmp.DiffToDelta(diffs))
		panic("Marshal output different from input")
	}
	return 1
}
