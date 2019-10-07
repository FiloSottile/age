package age_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/FiloSottile/age/internal/age"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

func TestX25519RoundTrip(t *testing.T) {
	var secretKey, publicKey, fileKey [32]byte
	if _, err := rand.Read(secretKey[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(fileKey[:]); err != nil {
		t.Fatal(err)
	}
	curve25519.ScalarBaseMult(&publicKey, &secretKey)

	r, err := age.NewX25519Recipient(publicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	i, err := age.NewX25519Identity(secretKey[:])
	if err != nil {
		t.Fatal(err)
	}

	if r.Type() != i.Type() || r.Type() != "X25519" {
		t.Errorf("invalid Type values: %v, %v", r.Type(), i.Type())
	}

	block, err := r.Wrap(fileKey[:])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v", block)

	out, err := i.Unwrap(block)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fileKey[:], out) {
		t.Errorf("invalid output: %x, expected %x", out, fileKey[:])
	}
}

func TestScryptRoundTrip(t *testing.T) {
	password := "twitch.tv/filosottile"

	r, err := age.NewScryptRecipient(password)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(1 << 15)
	i, err := age.NewScryptIdentity(password)
	if err != nil {
		t.Fatal(err)
	}

	if r.Type() != i.Type() || r.Type() != "scrypt" {
		t.Errorf("invalid Type values: %v, %v", r.Type(), i.Type())
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey[:]); err != nil {
		t.Fatal(err)
	}
	block, err := r.Wrap(fileKey[:])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v", block)

	out, err := i.Unwrap(block)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fileKey[:], out) {
		t.Errorf("invalid output: %x, expected %x", out, fileKey[:])
	}
}

func TestSSHRSARoundTrip(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 768)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&pk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	r, err := age.NewSSHRSARecipient(pub)
	if err != nil {
		t.Fatal(err)
	}
	i, err := age.NewSSHRSAIdentity(pk)
	if err != nil {
		t.Fatal(err)
	}

	if r.Type() != i.Type() || r.Type() != "ssh-rsa" {
		t.Errorf("invalid Type values: %v, %v", r.Type(), i.Type())
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey[:]); err != nil {
		t.Fatal(err)
	}
	block, err := r.Wrap(fileKey[:])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v", block)

	out, err := i.Unwrap(block)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(fileKey[:], out) {
		t.Errorf("invalid output: %x, expected %x", out, fileKey[:])
	}
}
