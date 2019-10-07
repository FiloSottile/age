// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package age

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"github.com/FiloSottile/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

type ScryptRecipient struct {
	password   []byte
	workFactor int
}

var _ Recipient = &ScryptRecipient{}

func (*ScryptRecipient) Type() string { return "scrypt" }

func NewScryptRecipient(password string) (*ScryptRecipient, error) {
	if len(password) == 0 {
		return nil, errors.New("empty scrypt password")
	}
	r := &ScryptRecipient{
		password:   []byte(password),
		workFactor: 1 << 18, // 1s on a modern machine
	}
	return r, nil
}

func (r *ScryptRecipient) SetWorkFactor(N int) {
	// TODO: automatically scale this to 1s (with a min) in the CLI.
	r.workFactor = N
}

func (r *ScryptRecipient) Wrap(fileKey []byte) (*format.Recipient, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}

	N := r.workFactor
	l := &format.Recipient{
		Type: "scrypt",
		Args: []string{format.EncodeToString(salt), strconv.Itoa(N)},
	}

	k, err := scrypt.Key(r.password, salt, N, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate scrypt hash: %v", err)
	}

	wrappedKey, err := aeadEncrypt(k, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = []byte(format.EncodeToString(wrappedKey) + "\n")

	return l, nil
}

type ScryptIdentity struct {
	password      []byte
	maxWorkFactor int
}

var _ Identity = &ScryptIdentity{}

func (*ScryptIdentity) Type() string { return "scrypt" }

func NewScryptIdentity(password string) (*ScryptIdentity, error) {
	if len(password) == 0 {
		return nil, errors.New("empty scrypt password")
	}
	i := &ScryptIdentity{
		password:      []byte(password),
		maxWorkFactor: 1 << 22, // 15s on a modern machine
	}
	return i, nil
}

func (i *ScryptIdentity) SetMaxWorkFactor(N int) {
	i.maxWorkFactor = N
}

func (i *ScryptIdentity) Unwrap(block *format.Recipient) ([]byte, error) {
	if block.Type != "scrypt" {
		return nil, errors.New("wrong recipient block type")
	}
	if len(block.Args) != 2 {
		return nil, errors.New("invalid scrypt recipient block")
	}
	salt, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse scrypt salt: %v", err)
	}
	if len(salt) != 16 {
		return nil, errors.New("invalid scrypt recipient block")
	}
	N, err := strconv.Atoi(block.Args[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse scrypt work factor: %v", err)
	}
	if N > i.maxWorkFactor {
		return nil, fmt.Errorf("scrypt work factor too large: %v", N)
	}
	wrappedKey, err := format.DecodeString(string(block.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse scrypt recipient: %v", err)
	}

	k, err := scrypt.Key(i.password, salt, N, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate scrypt hash: %v", err)
	}

	fileKey, err := aeadDecrypt(k, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key: %v", err)
	}
	return fileKey, nil
}
