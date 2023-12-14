// Copyright 2023 The age Authors
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package plugin

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
	"filippo.io/age/internal/bech32"
)

func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	// TODO: deduplicate from cmd/age TestMain.
	case "age-plugin-test":
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
			os.Exit(0)
		default:
			panic(os.Args[1])
		}
	case "age-plugin-testpqc":
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
			os.Stdout.WriteString("-> labels postquantum\n\n")
			scanner.Scan() // ok
			scanner.Scan() // body
			os.Stdout.WriteString("-> done\n\n")
			os.Exit(0)
		default:
			panic(os.Args[1])
		}
	default:
		os.Exit(m.Run())
	}
}

func TestLabels(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows support is TODO")
	}
	temp := t.TempDir()
	testOnlyPluginPath = temp
	t.Cleanup(func() { testOnlyPluginPath = "" })
	ex, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(ex, filepath.Join(temp, "age-plugin-test")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(temp, "age-plugin-test"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(ex, filepath.Join(temp, "age-plugin-testpqc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(temp, "age-plugin-testpqc"), 0755); err != nil {
		t.Fatal(err)
	}

	name, err := bech32.Encode("age1test", nil)
	if err != nil {
		t.Fatal(err)
	}
	testPlugin, err := NewRecipient(name, &ClientUI{})
	if err != nil {
		t.Fatal(err)
	}
	namePQC, err := bech32.Encode("age1testpqc", nil)
	if err != nil {
		t.Fatal(err)
	}
	testPluginPQC, err := NewRecipient(namePQC, &ClientUI{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := age.Encrypt(io.Discard, testPluginPQC); err != nil {
		t.Errorf("expected one pqc to work, got %v", err)
	}
	if _, err := age.Encrypt(io.Discard, testPluginPQC, testPluginPQC); err != nil {
		t.Errorf("expected two pqc to work, got %v", err)
	}
	if _, err := age.Encrypt(io.Discard, testPluginPQC, testPlugin); err == nil {
		t.Errorf("expected one pqc and one normal to fail")
	}
	if _, err := age.Encrypt(io.Discard, testPlugin, testPluginPQC); err == nil {
		t.Errorf("expected one pqc and one normal to fail")
	}
}
