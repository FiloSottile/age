// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package age implements file encryption according to age-encryption.org/v1.
package age

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"filippo.io/age/internal/format"
	"filippo.io/age/internal/stream"
)

type Identity interface {
	Type() string
	Unwrap(block *format.Recipient) (fileKey []byte, err error)
}

type IdentityMatcher interface {
	Identity
	Matches(block *format.Recipient) error
}

var ErrIncorrectIdentity = errors.New("incorrect identity for recipient block")

type Recipient interface {
	Type() string
	Wrap(fileKey []byte) (*format.Recipient, error)
}

func Encrypt(dst io.Writer, recipients ...Recipient) (io.WriteCloser, error) {
	// stream.Writer takes a WriteCloser, and will propagate Close calls (so
	// that the ArmoredWriter will get closed), but we don't want to expose
	// that behavior to our caller.
	dstCloser := format.NopCloser(dst)
	return encrypt(dstCloser, recipients...)
}

func EncryptWithArmor(dst io.Writer, recipients ...Recipient) (io.WriteCloser, error) {
	dstCloser := format.ArmoredWriter(dst)
	return encrypt(dstCloser, recipients...)
}

func encrypt(dst io.WriteCloser, recipients ...Recipient) (io.WriteCloser, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients specified")
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		return nil, err
	}

	hdr := &format.Header{}
	for i, r := range recipients {
		if r.Type() == "scrypt" && len(recipients) != 1 {
			return nil, errors.New("an scrypt recipient must be the only one")
		}

		block, err := r.Wrap(fileKey)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap key for recipient #%d: %v", i, err)
		}
		hdr.Recipients = append(hdr.Recipients, block)
	}
	if mac, err := headerMAC(fileKey, hdr); err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %v", err)
	} else {
		hdr.MAC = mac
	}
	if err := hdr.Marshal(dst); err != nil {
		return nil, fmt.Errorf("failed to write header: %v", err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if _, err := dst.Write(nonce); err != nil {
		return nil, fmt.Errorf("failed to write nonce: %v", err)
	}

	return stream.NewWriter(streamKey(fileKey, nonce), dst)
}

func Decrypt(src io.Reader, identities ...Identity) (io.Reader, error) {
	if len(identities) == 0 {
		return nil, errors.New("no identities specified")
	}

	hdr, payload, err := format.Parse(src)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}
	if len(hdr.Recipients) > 20 {
		return nil, errors.New("too many recipients")
	}

	var fileKey []byte
RecipientsLoop:
	for _, r := range hdr.Recipients {
		if r.Type == "scrypt" && len(hdr.Recipients) != 1 {
			return nil, errors.New("an scrypt recipient must be the only one")
		}
		for _, i := range identities {
			if i.Type() != r.Type {
				continue
			}

			if i, ok := i.(IdentityMatcher); ok {
				err := i.Matches(r)
				if err != nil {
					if err == ErrIncorrectIdentity {
						continue
					}
					return nil, err
				}
			}

			fileKey, err = i.Unwrap(r)
			if err != nil {
				if err == ErrIncorrectIdentity {
					// TODO: we should collect these errors and return them as an
					// []error type with an Error method. That will require turning
					// ErrIncorrectIdentity into an interface or wrapper error.
					continue
				}
				return nil, err
			}

			break RecipientsLoop
		}
	}
	if fileKey == nil {
		return nil, errors.New("no identity matched a recipient")
	}

	if mac, err := headerMAC(fileKey, hdr); err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %v", err)
	} else if !hmac.Equal(mac, hdr.MAC) {
		return nil, errors.New("bad header MAC")
	}

	nonce := make([]byte, 16)
	if _, err := io.ReadFull(payload, nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %v", err)
	}

	return stream.NewReader(streamKey(fileKey, nonce), payload)
}
