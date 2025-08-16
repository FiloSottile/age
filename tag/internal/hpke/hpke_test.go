// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpke

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

func mustDecodeHex(t *testing.T, in string) []byte {
	t.Helper()
	b, err := hex.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseVectorSetup(vector string) map[string]string {
	vals := map[string]string{}
	for _, l := range strings.Split(vector, "\n") {
		fields := strings.Split(l, ": ")
		vals[fields[0]] = fields[1]
	}
	return vals
}

func parseVectorEncryptions(vector string) []map[string]string {
	vals := []map[string]string{}
	for _, section := range strings.Split(vector, "\n\n") {
		e := map[string]string{}
		for _, l := range strings.Split(section, "\n") {
			fields := strings.Split(l, ": ")
			e[fields[0]] = fields[1]
		}
		vals = append(vals, e)
	}
	return vals
}

func TestRFC9180Vectors(t *testing.T) {
	vectorsJSON, err := os.ReadFile("testdata/rfc9180-vectors.json")
	if err != nil {
		t.Fatal(err)
	}

	var vectors []struct {
		Name        string
		Setup       string
		Encryptions string
	}
	if err := json.Unmarshal(vectorsJSON, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			setup := parseVectorSetup(vector.Setup)

			kemID, err := strconv.Atoi(setup["kem_id"])
			if err != nil {
				t.Fatal(err)
			}
			kdfID, err := strconv.Atoi(setup["kdf_id"])
			if err != nil {
				t.Fatal(err)
			}
			aeadID, err := strconv.Atoi(setup["aead_id"])
			if err != nil {
				t.Fatal(err)
			}
			info := mustDecodeHex(t, setup["info"])
			pubKeyBytes := mustDecodeHex(t, setup["pkRm"])
			pub, err := parsePublicKey(uint16(kemID), pubKeyBytes)
			if err != nil {
				t.Fatal(err)
			}

			ephemeralPrivKey := mustDecodeHex(t, setup["skEm"])

			testingOnlyGenerateKey = func() *ecdh.PrivateKey {
				priv, err := parsePrivateKey(uint16(kemID), ephemeralPrivKey)
				if err != nil {
					t.Fatal(err)
				}
				return priv
			}
			t.Cleanup(func() { testingOnlyGenerateKey = nil })

			kemSender, err := DHKEMSender(pub)
			if err != nil {
				t.Fatal(err)
			}
			kdf, err := getKDF(uint16(kdfID))
			if err != nil {
				t.Fatal(err)
			}
			aead, err := getAEAD(uint16(aeadID))
			if err != nil {
				t.Fatal(err)
			}
			encap, sender, err := SetupSender(kemSender, kdf, aead, info)
			if err != nil {
				t.Fatal(err)
			}

			expectedEncap := mustDecodeHex(t, setup["enc"])
			if !bytes.Equal(encap, expectedEncap) {
				t.Errorf("unexpected encapsulated key, got: %x, want %x", encap, expectedEncap)
			}

			privKeyBytes := mustDecodeHex(t, setup["skRm"])
			priv, err := parsePrivateKey(uint16(kemID), privKeyBytes)
			if err != nil {
				t.Fatal(err)
			}

			kemRecipient, err := DHKEMRecipient(priv)
			if err != nil {
				t.Fatal(err)
			}
			recipient, err := SetupRecipient(kemRecipient, kdf, aead, info, encap)
			if err != nil {
				t.Fatal(err)
			}

			for _, ctx := range []*context{sender.context, recipient.context} {
				expectedKey := mustDecodeHex(t, setup["key"])
				if !bytes.Equal(ctx.key, expectedKey) {
					t.Errorf("unexpected key, got: %x, want %x", ctx.key, expectedKey)
				}
				expectedBaseNonce := mustDecodeHex(t, setup["base_nonce"])
				if !bytes.Equal(ctx.baseNonce, expectedBaseNonce) {
					t.Errorf("unexpected base nonce, got: %x, want %x", ctx.baseNonce, expectedBaseNonce)
				}
			}

			for _, enc := range parseVectorEncryptions(vector.Encryptions) {
				t.Run("seq num "+enc["sequence number"], func(t *testing.T) {
					seqNum, err := strconv.Atoi(enc["sequence number"])
					if err != nil {
						t.Fatal(err)
					}
					sender.seqNum = uint128{lo: uint64(seqNum)}
					recipient.seqNum = uint128{lo: uint64(seqNum)}
					expectedNonce := mustDecodeHex(t, enc["nonce"])
					computedNonce := sender.nextNonce()
					if !bytes.Equal(computedNonce, expectedNonce) {
						t.Errorf("unexpected nonce: got %x, want %x", computedNonce, expectedNonce)
					}

					expectedCiphertext := mustDecodeHex(t, enc["ct"])
					ciphertext, err := sender.Seal(mustDecodeHex(t, enc["aad"]), mustDecodeHex(t, enc["pt"]))
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(ciphertext, expectedCiphertext) {
						t.Errorf("unexpected ciphertext: got %x want %x", ciphertext, expectedCiphertext)
					}

					expectedPlaintext := mustDecodeHex(t, enc["pt"])
					plaintext, err := recipient.Open(mustDecodeHex(t, enc["aad"]), mustDecodeHex(t, enc["ct"]))
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(plaintext, expectedPlaintext) {
						t.Errorf("unexpected plaintext: got %x want %x", plaintext, expectedPlaintext)
					}
				})
			}
		})
	}
}

func parsePublicKey(kemID uint16, keyBytes []byte) (*ecdh.PublicKey, error) {
	switch kemID {
	case 0x0010: // DHKEM(P-256, HKDF-SHA256)
		return ecdh.P256().NewPublicKey(keyBytes)
	default:
		return nil, errors.New("unsupported KEM")
	}
}

func parsePrivateKey(kemID uint16, keyBytes []byte) (*ecdh.PrivateKey, error) {
	switch kemID {
	case 0x0010: // DHKEM(P-256, HKDF-SHA256)
		return ecdh.P256().NewPrivateKey(keyBytes)
	default:
		return nil, errors.New("unsupported KEM")
	}
}

func getKDF(kdfID uint16) (KDF, error) {
	switch kdfID {
	case 0x0001: // HKDF-SHA256
		return HKDFSHA256(), nil
	default:
		return nil, errors.New("unsupported KDF")
	}
}

func getAEAD(aeadID uint16) (AEAD, error) {
	switch aeadID {
	case 0x0003: // ChaCha20Poly1305
		return ChaCha20Poly1305(), nil
	default:
		return nil, errors.New("unsupported AEAD")
	}
}
