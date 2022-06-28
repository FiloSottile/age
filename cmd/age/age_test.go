// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"testing"

	"filippo.io/age"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"age": func() (exitCode int) {
			testOnlyPanicInsteadOfExit = true
			defer func() {
				if testOnlyDidExit {
					exitCode = recover().(int)
				}
			}()
			testOnlyConfigureScryptIdentity = func(r *age.ScryptRecipient) {
				r.SetWorkFactor(10)
			}
			main()
			return 0
		},
	}))
}

func TestScript(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
	})
}
