// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package age implements file encryption according to age-encryption.org/v1.
//
// This is a narrow copy of internal/age to allow encryption/decryption as a library.
package age

import (
	"crypto/rsa"
	"io"

	"golang.org/x/crypto/ssh"

	"filippo.io/age/internal/age"
)

type Identity = age.Identity

var ErrIncorrectIdentity = age.ErrIncorrectIdentity

type Recipient = age.Recipient

func Encrypt(dst io.Writer, recipients ...Recipient) (io.WriteCloser, error) {
	return age.Encrypt(dst, recipients...)
}

func EncryptWithArmor(dst io.Writer, recipients ...Recipient) (io.WriteCloser, error) {
	return age.EncryptWithArmor(dst, recipients...)
}

func Decrypt(src io.Reader, identities ...Identity) (io.Reader, error) {
	return age.Decrypt(src, identities...)
}

func NewScryptRecipient(password string) (Recipient, error) {
	return age.NewScryptRecipient(password)
}
func NewScryptIdentity(password string) (Identity, error) {
	return age.NewScryptIdentity(password)
}
func NewSSHRSARecipient(pk ssh.PublicKey) (Recipient, error) {
	return age.NewSSHRSARecipient(pk)
}
func NewSSHRSAIdentity(key *rsa.PrivateKey) (Identity, error) {
	return age.NewSSHRSAIdentity(key)
}
func NewX25519Recipient(publicKey []byte) (Recipient, error) {
	return age.NewX25519Recipient(publicKey)
}

func ParseX25519Recipient(s string) (Recipient, error) {
	return age.ParseX25519Recipient(s)
}
func NewX25519Identity(secretKey []byte) (Identity, error) {
	return age.NewX25519Identity(secretKey)
}
func GenerateX25519Identity() (Identity, error) {
	return age.GenerateX25519Identity()
}
func ParseX25519Identity(s string) (Identity, error) {
	return age.ParseX25519Identity(s)
}
