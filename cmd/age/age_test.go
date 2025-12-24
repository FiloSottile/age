// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"age": func() {
			testOnlyConfigureScryptIdentity = func(r *age.ScryptRecipient) {
				r.SetWorkFactor(10)
			}
			testOnlyFixedRandomWord = "four"
			main()
		},
		"age-plugin-test": func() {
			p, _ := plugin.New("test")
			p.HandleRecipient(func(data []byte) (age.Recipient, error) {
				return testPlugin{}, nil
			})
			p.HandleIdentity(func(data []byte) (age.Identity, error) {
				return testPlugin{}, nil
			})
			os.Exit(p.Main())
		},
	})
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

var buildExtraCommands = sync.OnceValue(func() error {
	bindir := filepath.SplitList(os.Getenv("PATH"))[0]
	// Build age-keygen and age-plugin-pq into the test binary directory.
	cmd := exec.Command("go", "build", "-o", bindir)
	if testing.CoverMode() != "" {
		cmd.Args = append(cmd.Args, "-cover")
	}
	cmd.Args = append(cmd.Args, "filippo.io/age/cmd/age-keygen")
	cmd.Args = append(cmd.Args, "filippo.io/age/extra/age-plugin-pq")
	cmd.Args = append(cmd.Args, "filippo.io/age/cmd/age-plugin-batchpass")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
})

func TestScript(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		Setup: func(e *testscript.Env) error {
			return buildExtraCommands()
		},
		// TODO: enable AGEDEBUG=plugin without breaking stderr checks.
	})
}
