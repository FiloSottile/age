// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
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
			testOnlyFixedRandomWord = "four"
			main()
			return 0
		},
		"age-plugin-test": func() (exitCode int) {
			// TODO: use plugin server package once it's available.
			switch os.Args[1] {
			case "--age-plugin=recipient-v1":
				scanner := bufio.NewScanner(os.Stdin)
				scanner.Scan() // add-recipient
				scanner.Scan() // body
				scanner.Scan() // grease
				scanner.Scan() // body
				scanner.Scan() // wrap-file-key
				scanner.Scan() // body
				fileKey := scanner.Text()
				scanner.Scan() // extension-labels
				scanner.Scan() // body
				scanner.Scan() // done
				scanner.Scan() // body
				os.Stdout.WriteString("-> recipient-stanza 0 test\n")
				os.Stdout.WriteString(fileKey + "\n")
				scanner.Scan() // ok
				scanner.Scan() // body
				os.Stdout.WriteString("-> done\n\n")
				return 0
			case "--age-plugin=identity-v1":
				scanner := bufio.NewScanner(os.Stdin)
				scanner.Scan() // add-identity
				scanner.Scan() // body
				scanner.Scan() // grease
				scanner.Scan() // body
				scanner.Scan() // recipient-stanza
				scanner.Scan() // body
				fileKey := scanner.Text()
				scanner.Scan() // done
				scanner.Scan() // body
				os.Stdout.WriteString("-> file-key 0\n")
				os.Stdout.WriteString(fileKey + "\n")
				scanner.Scan() // ok
				scanner.Scan() // body
				os.Stdout.WriteString("-> done\n\n")
				return 0
			default:
				return 1
			}
		},
	}))
}

func TestScript(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		// TODO: enable AGEDEBUG=plugin without breaking stderr checks.
	})
}
