package age

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/FiloSottile/age/internal/format"
	"golang.org/x/crypto/ssh"
)

const oaepLabel = "age-tool.com ssh-rsa"

type SSHRSARecipient struct {
	sshKey ssh.PublicKey
	pubKey *rsa.PublicKey
}

var _ Recipient = &SSHRSARecipient{}

func (*SSHRSARecipient) Type() string { return "ssh-rsa" }

func NewSSHRSARecipient(pk ssh.PublicKey) (*SSHRSARecipient, error) {
	if pk.Type() != "ssh-rsa" {
		return nil, errors.New("SSH public key is not an RSA key")
	}
	r := &SSHRSARecipient{
		sshKey: pk,
	}

	if pk, ok := pk.(ssh.CryptoPublicKey); ok {
		if pk, ok := pk.CryptoPublicKey().(*rsa.PublicKey); ok {
			r.pubKey = pk
		} else {
			return nil, errors.New("unexpected public key type")
		}
	} else {
		return nil, errors.New("pk does not implement ssh.CryptoPublicKey")
	}
	return r, nil
}

func (r *SSHRSARecipient) Wrap(fileKey []byte) (*format.Recipient, error) {
	h := sha256.New()
	h.Write(r.sshKey.Marshal())
	hh := h.Sum(nil)

	l := &format.Recipient{
		Type: "ssh-rsa",
		Args: []string{format.EncodeToString(hh[:4])},
	}

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
		r.pubKey, fileKey, []byte(oaepLabel))
	if err != nil {
		return nil, err
	}
	l.Body = []byte(format.EncodeToString(wrappedKey) + "\n")

	return l, nil
}

type SSHRSAIdentity struct {
	k      *rsa.PrivateKey
	sshKey ssh.PublicKey
}

var _ Identity = &SSHRSAIdentity{}

func (*SSHRSAIdentity) Type() string { return "ssh-rsa" }

func NewSSHRSAIdentity(key *rsa.PrivateKey) (*SSHRSAIdentity, error) {
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	i := &SSHRSAIdentity{
		k: key, sshKey: s.PublicKey(),
	}
	return i, nil
}

func (i *SSHRSAIdentity) Unwrap(block *format.Recipient) ([]byte, error) {
	if block.Type != "ssh-rsa" {
		return nil, errors.New("wrong recipient block type")
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid ssh-rsa recipient block")
	}
	hash, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh-rsa recipient: %v", err)
	}
	if len(hash) != 4 {
		return nil, errors.New("invalid ssh-rsa recipient block")
	}
	wrappedKey, err := format.DecodeString(string(block.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh-rsa recipient: %v", err)
	}

	h := sha256.New()
	h.Write(i.sshKey.Marshal())
	hh := h.Sum(nil)
	if !bytes.Equal(hh[:4], hash) {
		return nil, errors.New("wrong ssh-rsa key")
	}

	fileKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, i.k,
		wrappedKey, []byte(oaepLabel))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key: %v", err)
	}
	return fileKey, nil
}
