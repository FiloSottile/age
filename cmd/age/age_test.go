// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
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
			testOnlyFixedRandomWord = "four"
			main()
			return 0
		},
		"age-plugin-test": func() (exitCode int) {
			p, _ := plugin.New("test")
			p.HandleRecipient(func(data []byte) (age.Recipient, error) {
				return testPlugin{}, nil
			})
			p.HandleIdentity(func(data []byte) (age.Identity, error) {
				return testPlugin{}, nil
			})
			return p.Main()
		},
	}))
}

type testPlugin struct{}

func (testPlugin) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: "test", Body: fileKey}}, nil
}

func (testPlugin) Unwrap(ss []*age.Stanza) ([]byte, error) {
	if len(ss) == 1 && ss[0].Type == "test" {
		return ss[0].Body, nil
	}
	return nil, age.ErrIncorrectIdentity
}

func TestScript(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		// TODO: enable AGEDEBUG=plugin without breaking stderr checks.
	})
}
