// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agessh

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

// EncryptedSSHIdentity is an age.Identity implementation based on a passphrase
// encrypted SSH private key.
//
// It requests the passphrase only if the public key matches a recipient stanza.
// If the application knows it will always have to decrypt the private key, it
// would be simpler to use ssh.ParseRawPrivateKeyWithPassphrase directly and
// pass the result to NewEd25519Identity or NewRSAIdentity.
type EncryptedSSHIdentity struct {
	pubKey     ssh.PublicKey
	recipient  age.Recipient
	pemBytes   []byte
	passphrase func() ([]byte, error)

	decrypted age.Identity
}

// NewEncryptedSSHIdentity returns a new EncryptedSSHIdentity.
//
// pubKey must be the public key associated with the encrypted private key, and
// it must have type "ssh-ed25519" or "ssh-rsa". For OpenSSH encrypted files it
// can be extracted from an ssh.PassphraseMissingError, otherwise it can often
// be found in ".pub" files.
//
// pemBytes must be a valid input to ssh.ParseRawPrivateKeyWithPassphrase.
// passphrase is a callback that will be invoked by Unwrap when the passphrase
// is necessary.
func NewEncryptedSSHIdentity(pubKey ssh.PublicKey, pemBytes []byte, passphrase func() ([]byte, error)) (*EncryptedSSHIdentity, error) {
	i := &EncryptedSSHIdentity{
		pubKey:     pubKey,
		pemBytes:   pemBytes,
		passphrase: passphrase,
	}
	switch t := pubKey.Type(); t {
	case "ssh-ed25519":
		r, err := NewEd25519Recipient(pubKey)
		if err != nil {
			return nil, err
		}
		i.recipient = r
	case "ssh-rsa":
		r, err := NewRSARecipient(pubKey)
		if err != nil {
			return nil, err
		}
		i.recipient = r
	default:
		return nil, fmt.Errorf("unsupported SSH key type: %v", t)
	}
	return i, nil
}

var _ age.Identity = &EncryptedSSHIdentity{}

func (i *EncryptedSSHIdentity) Recipient() age.Recipient {
	return i.recipient
}

// Unwrap implements age.Identity. If the private key is still encrypted, and
// any of the stanzas match the public key, it will request the passphrase. The
// decrypted private key will be cached after the first successful invocation.
func (i *EncryptedSSHIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	if i.decrypted != nil {
		return i.decrypted.Unwrap(stanzas)
	}

	var match bool
	for _, s := range stanzas {
		if s.Type != i.pubKey.Type() {
			continue
		}
		if len(s.Args) < 1 {
			return nil, fmt.Errorf("invalid %v recipient block", i.pubKey.Type())
		}
		if s.Args[0] != sshFingerprint(i.pubKey) {
			continue
		}
		match = true
		break
	}
	if !match {
		return nil, age.ErrIncorrectIdentity
	}

	passphrase, err := i.passphrase()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain passphrase: %v", err)
	}
	k, err := ssh.ParseRawPrivateKeyWithPassphrase(i.pemBytes, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SSH key file: %v", err)
	}

	var pubKey interface {
		Equal(x crypto.PublicKey) bool
	}
	switch k := k.(type) {
	case *ed25519.PrivateKey:
		i.decrypted, err = NewEd25519Identity(*k)
		pubKey = k.Public().(ed25519.PublicKey)
	// ParseRawPrivateKey returns inconsistent types. See Issue 429.
	case ed25519.PrivateKey:
		i.decrypted, err = NewEd25519Identity(k)
		pubKey = k.Public().(ed25519.PublicKey)
	case *rsa.PrivateKey:
		i.decrypted, err = NewRSAIdentity(k)
		pubKey = &k.PublicKey
	default:
		return nil, fmt.Errorf("unexpected SSH key type: %T", k)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid SSH key: %v", err)
	}

	if exp := i.pubKey.(ssh.CryptoPublicKey).CryptoPublicKey(); !pubKey.Equal(exp) {
		return nil, fmt.Errorf("mismatched private and public SSH key")
	}

	return i.decrypted.Unwrap(stanzas)
}
