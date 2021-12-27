package agemobile

import (
	"io"
	"os"
	"testing"

	"filippo.io/age"
)

func TestDecrypt(t *testing.T) {
	txt := "Hello World"
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Encrypt(id.Recipient().String(), txt, false)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := Decrypt(id.String(), out)
	if err != nil {
		t.Fatal(err)
	}
	if dec != txt {
		t.Fatalf("Expected %v but got %v\n", txt, dec)
	}
}

func TestDecryptArmor(t *testing.T) {
	txt := "Hello World"
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Encrypt(id.Recipient().String(), txt, true)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := Decrypt(id.String(), out)
	if err != nil {
		t.Fatal(err)
	}
	if dec != txt {
		t.Fatalf("Expected %v but got %v\n", txt, dec)
	}
}

func TestDecryptFile(t *testing.T) {
	txt := "Hello World"
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Encrypt(id.Recipient().String(), txt, false)
	if err != nil {
		t.Fatal(err)
	}
	fdin, err := os.CreateTemp("", "age_input_*")
	if err != nil {
		t.Fatal(err)
	}
	defer fdin.Close()

	io.WriteString(fdin, out)

	fdout, err := os.CreateTemp("", "age_*")
	if err != nil {
		t.Fatal(err)
	}
	defer fdout.Close()

	err = DecryptFile(id.String(), fdin.Name(), fdout.Name())
	if err != nil {
		t.Fatal(err)
	}

	buff, err := io.ReadAll(fdout)
	if err != nil {
		t.Fatal(err)
	}
	if string(buff) != txt {
		t.Fatalf("expected decrypted %v but got %v\n", txt, string(buff))
	}
}

func TestDecryptFileArmor(t *testing.T) {
	txt := "Hello World"
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Encrypt(id.Recipient().String(), txt, true)
	if err != nil {
		t.Fatal(err)
	}
	fdin, err := os.CreateTemp("", "age_input_*")
	if err != nil {
		t.Fatal(err)
	}
	defer fdin.Close()

	io.WriteString(fdin, out)

	fdout, err := os.CreateTemp("", "age_*")
	if err != nil {
		t.Fatal(err)
	}
	defer fdout.Close()

	err = DecryptFile(id.String(), fdin.Name(), fdout.Name())
	if err != nil {
		t.Fatal(err)
	}

	buff, err := io.ReadAll(fdout)
	if err != nil {
		t.Fatal(err)
	}
	if string(buff) != txt {
		t.Fatalf("expected decrypted %v but got %v\n", txt, string(buff))
	}
}
