// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package agessh

import (
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

// EncryptedSSHIdentity is an age.IdentityMatcher implementation based on a
// passphrase encrypted SSH private key.
//
// It provides public key based matching and deferred decryption so the
// passphrase is only requested if necessary. If the application knows it will
// unconditionally have to decrypt the private key, it would be simpler to use
// ssh.ParseRawPrivateKeyWithPassphrase directly and pass the result to
// NewEd25519Identity or NewRSAIdentity.
type EncryptedSSHIdentity struct {
	pubKey     ssh.PublicKey
	pemBytes   []byte
	passphrase func() ([]byte, error)

	decrypted age.Identity
}

// NewEncryptedSSHIdentity returns a new EncryptedSSHIdentity.
//
// pubKey must be the public key associated with the encrypted private key, and
// it must have type "ssh-ed25519" or "ssh-rsa". For OpenSSH encrypted files it
// can be extracted from an ssh.PassphraseMissingError, otherwise in can often
// be found in ".pub" files.
//
// pemBytes must be a valid input to ssh.ParseRawPrivateKeyWithPassphrase.
// passphrase is a callback that will be invoked by Unwrap when the passphrase
// is necessary.
func NewEncryptedSSHIdentity(pubKey ssh.PublicKey, pemBytes []byte, passphrase func() ([]byte, error)) (*EncryptedSSHIdentity, error) {
	switch t := pubKey.Type(); t {
	case "ssh-ed25519", "ssh-rsa":
	default:
		return nil, fmt.Errorf("unsupported SSH key type: %v", t)
	}
	return &EncryptedSSHIdentity{
		pubKey:     pubKey,
		pemBytes:   pemBytes,
		passphrase: passphrase,
	}, nil
}

var _ age.IdentityMatcher = &EncryptedSSHIdentity{}

// Type returns the type of the underlying private key, "ssh-ed25519" or "ssh-rsa".
func (i *EncryptedSSHIdentity) Type() string {
	return i.pubKey.Type()
}

// Unwrap implements age.Identity. If the private key is still encrypted, it
// will request the passphrase. The decrypted private key will be cached after
// the first successful invocation.
func (i *EncryptedSSHIdentity) Unwrap(block *age.Stanza) (fileKey []byte, err error) {
	if i.decrypted != nil {
		return i.decrypted.Unwrap(block)
	}

	passphrase, err := i.passphrase()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain passphrase: %v", err)
	}
	k, err := ssh.ParseRawPrivateKeyWithPassphrase(i.pemBytes, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SSH key file: %v", err)
	}

	switch k := k.(type) {
	case *ed25519.PrivateKey:
		i.decrypted, err = NewEd25519Identity(*k)
	case *rsa.PrivateKey:
		i.decrypted, err = NewRSAIdentity(k)
	default:
		return nil, fmt.Errorf("unexpected SSH key type: %T", k)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid SSH key: %v", err)
	}
	if i.decrypted.Type() != i.pubKey.Type() {
		return nil, fmt.Errorf("mismatched SSH key type: got %q, expected %q", i.decrypted.Type(), i.pubKey.Type())
	}

	return i.decrypted.Unwrap(block)
}

// Match implements age.IdentityMatcher without decrypting the private key, to
// ensure the passphrase is only obtained if necessary.
func (i *EncryptedSSHIdentity) Match(block *age.Stanza) error {
	if block.Type != i.Type() {
		return age.ErrIncorrectIdentity
	}
	if len(block.Args) < 1 {
		return fmt.Errorf("invalid %v recipient block", i.Type())
	}

	if block.Args[0] != sshFingerprint(i.pubKey) {
		return age.ErrIncorrectIdentity
	}
	return nil
}
