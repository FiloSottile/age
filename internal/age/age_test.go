package age_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"testing"

	"github.com/FiloSottile/age/internal/age"
	"golang.org/x/crypto/curve25519"
)

const helloWorld = "Hello, Twitch!"

func TestEncryptDecryptX25519(t *testing.T) {
	var secretKeyA, publicKeyA, secretKeyB, publicKeyB [32]byte
	if _, err := rand.Read(secretKeyA[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(secretKeyB[:]); err != nil {
		t.Fatal(err)
	}
	curve25519.ScalarBaseMult(&publicKeyA, &secretKeyA)
	curve25519.ScalarBaseMult(&publicKeyB, &secretKeyB)

	rA, err := age.NewX25519Recipient(publicKeyA[:])
	if err != nil {
		t.Fatal(err)
	}
	rB, err := age.NewX25519Recipient(publicKeyB[:])
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

	t.Logf("%s", buf.Bytes())

	i, err := age.NewX25519Identity(secretKeyB[:])
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

func TestEncryptDecryptScrypt(t *testing.T) {
	password := "twitch.tv/filosottile"

	r, err := age.NewScryptRecipient(password)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(1 << 15)
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, helloWorld); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("%s", buf.Bytes())

	i, err := age.NewScryptIdentity(password)
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
