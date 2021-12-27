package agemobile

import (
	"io"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func TestEncrypt(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Encrypt(a.Recipient().String(), "Hello World", false)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncryptArmor(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	enc, err := Encrypt(a.Recipient().String(), "Hello World", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(enc, armor.Header) {
		t.Fatalf("expected armor encrypted file but got %v", enc)
	}
}

func TestEncryptFile(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	fdin, err := os.CreateTemp("", "age_input_*")
	if err != nil {
		t.Fatal(err)
	}
	defer fdin.Close()

	if _, err := io.WriteString(fdin, "Hello World"); err != nil {
		t.Fatal(err)
	}

	fdout, err := os.CreateTemp("", "age_*")
	if err != nil {
		t.Fatal(err)
	}
	defer fdout.Close()

	err = EncryptFile(a.Recipient().String(), fdin.Name(), fdout.Name(), false)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := fdout.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() == 0 {
		t.Fatal("expected file not to be empty")
	}
}

func TestEncryptFileArmor(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	fdin, err := os.CreateTemp("", "age_input_*")
	if err != nil {
		t.Fatal(err)
	}
	defer fdin.Close()

	if _, err := io.WriteString(fdin, "Hello World"); err != nil {
		t.Fatal(err)
	}

	fdout, err := os.CreateTemp("", "age_*")
	if err != nil {
		t.Fatal(err)
	}
	defer fdout.Close()

	err = EncryptFile(a.Recipient().String(), fdin.Name(), fdout.Name(), true)
	if err != nil {
		t.Fatal(err)
	}
	buff, err := io.ReadAll(fdout)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(buff), armor.Header) {
		t.Fatalf("expected armor encrypted file but got %v", string(buff))
	}
}
