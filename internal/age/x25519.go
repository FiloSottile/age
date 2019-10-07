package age

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/FiloSottile/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const x25519Label = "age-tool.com X25519"

type X25519Recipient struct {
	theirPublicKey [32]byte
}

var _ Recipient = &X25519Recipient{}

func (*X25519Recipient) Type() string { return "X25519" }

func NewX25519Recipient(publicKey []byte) (*X25519Recipient, error) {
	if len(publicKey) != 32 {
		return nil, errors.New("invalid X25519 public key")
	}
	r := &X25519Recipient{}
	copy(r.theirPublicKey[:], publicKey)
	return r, nil
}

func (r *X25519Recipient) Wrap(fileKey []byte) (*format.Recipient, error) {
	var ephemeral, ourPublicKey [32]byte
	if _, err := rand.Read(ephemeral[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&ourPublicKey, &ephemeral)

	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &ephemeral, &r.theirPublicKey)

	l := &format.Recipient{
		Type: "X25519",
		Args: []string{format.EncodeToString(ourPublicKey[:])},
	}

	salt := make([]byte, 0, 32*2)
	salt = append(salt, ourPublicKey[:]...)
	salt = append(salt, r.theirPublicKey[:]...)
	h := hkdf.New(sha256.New, sharedSecret[:], salt, []byte(x25519Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = []byte(format.EncodeToString(wrappedKey) + "\n")

	return l, nil
}

type X25519Identity struct {
	secretKey, ourPublicKey [32]byte
}

var _ Identity = &X25519Identity{}

func (*X25519Identity) Type() string { return "X25519" }

func NewX25519Identity(secretKey []byte) (*X25519Identity, error) {
	if len(secretKey) != 32 {
		return nil, errors.New("invalid X25519 secret key")
	}
	i := &X25519Identity{}
	copy(i.secretKey[:], secretKey)
	curve25519.ScalarBaseMult(&i.ourPublicKey, &i.secretKey)
	return i, nil
}

func (i *X25519Identity) Unwrap(block *format.Recipient) ([]byte, error) {
	if block.Type != "X25519" {
		return nil, errors.New("wrong recipient block type")
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid X25519 recipient block")
	}
	publicKey, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X25519 recipient: %v", err)
	}
	if len(publicKey) != 32 {
		return nil, errors.New("invalid X25519 recipient block")
	}
	wrappedKey, err := format.DecodeString(string(block.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse X25519 recipient: %v", err)
	}

	var sharedSecret, theirPublicKey [32]byte
	copy(theirPublicKey[:], publicKey)
	curve25519.ScalarMult(&sharedSecret, &i.secretKey, &theirPublicKey)

	salt := make([]byte, 0, 32*2)
	salt = append(salt, theirPublicKey[:]...)
	salt = append(salt, i.ourPublicKey[:]...)
	h := hkdf.New(sha256.New, sharedSecret[:], salt, []byte(x25519Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	fileKey, err := aeadDecrypt(wrappingKey, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key: %v", err)
	}
	return fileKey, nil
}
