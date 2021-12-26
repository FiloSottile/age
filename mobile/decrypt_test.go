package mobile

import (
	"testing"

	"filippo.io/age"
)

func TestDecrypt(t *testing.T) {
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
