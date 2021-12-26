package mobile

import (
	"testing"

	"filippo.io/age"
)

func TestEncrypt(t *testing.T) {
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	_, err = Encrypt(a.Recipient().String(), "Hello World", true)
	if err != nil {
		t.Fatal(err)
	}

}
