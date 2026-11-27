// Copyright 2023 The age Authors
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package plugin

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/format"
)

func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case "age-plugin-test":
		p, _ := New("test")
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			return testRecipient{}, nil
		})
		os.Exit(p.Main())
	case "age-plugin-testpqc":
		p, _ := New("testpqc")
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			return testPQCRecipient{}, nil
		})
		os.Exit(p.Main())
	case "age-plugin-error":
		p, _ := New("error")
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			return nil, errors.New("oh my, an error occurred")
		})
		p.HandleIdentity(func(data []byte) (age.Identity, error) {
			return nil, errors.New("oh my, an error occurred")
		})
		os.Exit(p.Main())
	default:
		os.Exit(m.Run())
	}
}

type testRecipient struct{}

func (testRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: "test", Body: fileKey}}, nil
}

type testPQCRecipient struct{}

var _ age.RecipientWithLabels = testPQCRecipient{}

func (testPQCRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: "test", Body: fileKey}}, nil
}

func (testPQCRecipient) WrapWithLabels(fileKey []byte) ([]*age.Stanza, []string, error) {
	return []*age.Stanza{{Type: "test", Body: fileKey}}, []string{"postquantum"}, nil
}

func TestIdentityV1NegativeIndex(t *testing.T) {
	p, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	p.HandleIdentity(func([]byte) (age.Identity, error) { return nil, nil })
	stderr := &bytes.Buffer{}
	p.SetIO(strings.NewReader("-> recipient-stanza -1 X25519\n\n"), io.Discard, stderr)
	if code := p.IdentityV1(); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	want := "unexpected file index -1, previous was -1"
	if got := stderr.String(); got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}

func TestPluginNameCase(t *testing.T) {
	p, err := New("MixedCase")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "mixedcase" {
		t.Errorf("Plugin.Name = %q", p.Name())
	}
	id, err := NewIdentityWithoutData("MixedCase", &ClientUI{})
	if err != nil {
		t.Fatal(err)
	}
	if id.Name() != "mixedcase" {
		t.Errorf("Identity.Name = %q", id.Name())
	}
	if _, err := New("\u212a"); err == nil {
		t.Error("New accepted a non-ASCII name")
	}
}

func TestRequestValueEmpty(t *testing.T) {
	p, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	p.SetIO(nil, io.Discard, io.Discard)
	p.sr = format.NewStanzaReader(bufio.NewReader(strings.NewReader("-> ok\n\n")))
	value, err := p.RequestValue("prompt", true)
	if err != nil {
		t.Fatal(err)
	}
	if value != "" {
		t.Errorf("value = %q", value)
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

	t.Run("debug does not log protocol payloads", func(t *testing.T) {
		t.Setenv("AGEDEBUG", "plugin")
		stderrReader, stderrWriter, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer stderrReader.Close()
		originalStderr := os.Stderr
		os.Stderr = stderrWriter
		defer func() { os.Stderr = originalStderr }()
		defer stderrWriter.Close()

		conn, err := openClientConnection("test", "recipient-v1")
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if conn != nil {
				conn.Close()
			}
		}()
		secret := []byte("secret protocol payload")
		recipient := EncodeRecipient("test", nil)
		if err := writeStanza(conn, "add-recipient", recipient); err != nil {
			t.Fatal(err)
		}
		identity := EncodeIdentity("test", []byte("secret identity payload"))
		if err := writeStanza(conn, "add-identity", identity); err != nil {
			t.Fatal(err)
		}
		if err := writeStanzaWithBody(conn, "wrap-file-key", secret); err != nil {
			t.Fatal(err)
		}
		if err := writeStanza(conn, "done"); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		conn = nil
		stderrWriter.Close()
		logged, err := io.ReadAll(stderrReader)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{format.EncodeToString(secret), identity} {
			if bytes.Contains(logged, []byte(secret)) {
				t.Errorf("debug output contains secret protocol payload: %q", logged)
			}
		}
	})
}

func TestNotFound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows support is TODO")
	}

	r := EncodeRecipient("nonexistentplugin", nil)
	t.Log(r)
	testPluginRecipient, err := NewRecipient(r, &ClientUI{})
	if err != nil {
		t.Fatal(err)
	}
	var e *NotFoundError
	if _, err := age.Encrypt(io.Discard, testPluginRecipient); err == nil {
		t.Errorf("expected error for nonexistent plugin")
	} else if !errors.As(err, &e) {
		t.Errorf("expected NotFoundError, got %T: %v", err, err)
	} else if e.Name != "nonexistentplugin" {
		t.Errorf("expected NotFoundError.Name to be nonexistentplugin, got %q", e.Name)
	} else if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("expected error to wrap exec.ErrNotFound, got: %v", err)
	}

	buf := &bytes.Buffer{}
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	w, err := age.Encrypt(buf, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	w.Close()

	i := EncodeIdentity("nonexistentplugin", nil)
	t.Log(i)
	testPluginIdentity, err := NewIdentity(i, &ClientUI{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(buf, testPluginIdentity); err == nil {
		t.Errorf("expected error for nonexistent plugin")
	} else if errors.As(err, new(*age.NoIdentityMatchError)) {
		t.Errorf("expected NotFoundError, got NoIdentityMatchError: %v", err)
	} else if !errors.As(err, &e) {
		t.Errorf("expected NotFoundError, got %T: %v", err, err)
	} else if e.Name != "nonexistentplugin" {
		t.Errorf("expected NotFoundError.Name to be nonexistentplugin, got %q", e.Name)
	} else if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("expected error to wrap exec.ErrNotFound, got: %v", err)
	}
}

func TestPluginError(t *testing.T) {
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
	if err := os.Link(ex, filepath.Join(temp, "age-plugin-error")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(temp, "age-plugin-error"), 0755); err != nil {
		t.Fatal(err)
	}

	r := EncodeRecipient("error", nil)
	testPluginRecipient, err := NewRecipient(r, &ClientUI{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Encrypt(io.Discard, testPluginRecipient); err == nil {
		t.Errorf("expected error from plugin")
	} else if !strings.Contains(err.Error(), "oh my, an error occurred") {
		t.Errorf("expected plugin error, got: %v", err)
	}

	buf := &bytes.Buffer{}
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	w, err := age.Encrypt(buf, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	w.Close()

	i := EncodeIdentity("error", nil)
	testPluginIdentity, err := NewIdentity(i, &ClientUI{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(buf, testPluginIdentity); err == nil {
		t.Errorf("expected error from plugin")
	} else if !strings.Contains(err.Error(), "oh my, an error occurred") {
		t.Errorf("expected plugin error, got: %v", err)
	}
}
