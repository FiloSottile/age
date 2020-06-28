package keywrap_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"testing"

	"filippo.io/age/cmd/internal/keywrap"
	"filippo.io/age/internal/age"
	"golang.org/x/crypto/curve25519"
)

const password = "yellow submarine"
const helloWorld = "Hello, Twitch!"

func TestEncryptDecryptProtectedX25519(t *testing.T) {
	secretKeyA := make([]byte, curve25519.ScalarSize)
	secretKeyB := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(secretKeyA); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(secretKeyB); err != nil {
		t.Fatal(err)
	}
	publicKeyA, _ := curve25519.X25519(secretKeyA, curve25519.Basepoint)
	publicKeyB, _ := curve25519.X25519(secretKeyB, curve25519.Basepoint)

	rA, err := age.NewX25519Recipient(publicKeyA)
	if err != nil {
		t.Fatal(err)
	}
	rB, err := age.NewX25519Recipient(publicKeyB)
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, rA, rB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, helloWorld); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	i, err := keywrap.NewProtectedX25519Identity([]byte(secretKeyB), []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	out, err := age.Decrypt(buf, i)
	if err != nil {
		t.Fatal(err)
	}
	outBytes, err := ioutil.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(outBytes) != helloWorld {
		t.Errorf("wrong data: %q, excepted %q", outBytes, helloWorld)
	}
}
