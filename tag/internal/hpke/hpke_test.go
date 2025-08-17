// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpke

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"

	"filippo.io/mlkem768"
)

func mustDecodeHex(t *testing.T, in string) []byte {
	t.Helper()
	b, err := hex.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	vectorsJSON, err := os.ReadFile("testdata/hpke-pq.json")
	if err != nil {
		t.Fatal(err)
	}

	var vectors []struct {
		Mode        uint16 `json:"mode"`
		KEM         uint16 `json:"kem_id"`
		KDF         uint16 `json:"kdf_id"`
		AEAD        uint16 `json:"aead_id"`
		Info        string `json:"info"`
		EncapRand   string `json:"encap_rand"`
		IkmR        string `json:"ikmR"`
		SkRm        string `json:"skRm"`
		PkRm        string `json:"pkRm"`
		Enc         string `json:"enc"`
		SuiteID     string `json:"suite_id"`
		Key         string `json:"key"`
		BaseNonce   string `json:"base_nonce"`
		Encryptions []struct {
			Aad   string `json:"aad"`
			Ct    string `json:"ct"`
			Nonce string `json:"nonce"`
			Pt    string `json:"pt"`
		} `json:"encryptions"`
	}
	if err := json.Unmarshal(vectorsJSON, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, vector := range vectors {
		name := fmt.Sprintf("kem %04x kdf %04x aead %04x",
			vector.KEM, vector.KDF, vector.AEAD)
		t.Run(name, func(t *testing.T) {
			info := mustDecodeHex(t, vector.Info)
			pubKeyBytes := mustDecodeHex(t, vector.PkRm)
			pubT, pubPQ := parsePublicKey(t, vector.KEM, pubKeyBytes)

			var kemSender KEMSender
			if pubPQ != nil {
				kemSender, err = QSFSender(pubT, pubPQ)
			} else {
				kemSender, err = DHKEMSender(pubT)
			}
			if err != nil {
				t.Fatal(err)
			}
			kdf, err := getKDF(vector.KDF)
			if err != nil {
				t.Fatal(err)
			}
			aead, err := getAEAD(vector.AEAD)
			if err != nil {
				t.Fatal(err)
			}

			encapsRand := mustDecodeHex(t, vector.EncapRand)
			setupEncapDerand(t, vector.KEM, encapsRand, pubPQ, kdf)

			encap, sender, err := SetupSender(kemSender, kdf, aead, info)
			if err != nil {
				t.Fatal(err)
			}

			expectedEncap := mustDecodeHex(t, vector.Enc)
			if !bytes.Equal(encap, expectedEncap) {
				t.Errorf("unexpected encapsulated key, got: %x, want %x", encap, expectedEncap)
			}

			privKeyBytes := mustDecodeHex(t, vector.SkRm)
			privT, privQ := parsePrivateKey(t, vector.KEM, privKeyBytes)

			var kemRecipient KEMRecipient
			if privQ != nil {
				kemRecipient, err = QSFRecipient(privT, privQ)
			} else {
				kemRecipient, err = DHKEMRecipient(privT)
			}
			if err != nil {
				t.Fatal(err)
			}
			recipient, err := SetupRecipient(kemRecipient, kdf, aead, info, encap)
			if err != nil {
				t.Fatal(err)
			}

			for i, ctx := range []*context{sender.context, recipient.context} {
				name := []string{"sender", "recipient"}[i]
				expectedSuiteID := mustDecodeHex(t, vector.SuiteID)
				if !bytes.Equal(ctx.suiteID, expectedSuiteID) {
					t.Errorf("%s: unexpected suite ID, got: %x, want %x", name, ctx.suiteID, expectedSuiteID)
				}
				expectedKey := mustDecodeHex(t, vector.Key)
				if !bytes.Equal(ctx.key, expectedKey) {
					t.Errorf("%s: unexpected key, got: %x, want %x", name, ctx.key, expectedKey)
				}
				expectedBaseNonce := mustDecodeHex(t, vector.BaseNonce)
				if !bytes.Equal(ctx.baseNonce, expectedBaseNonce) {
					t.Errorf("%s: unexpected base nonce, got: %x, want %x", name, ctx.baseNonce, expectedBaseNonce)
				}
			}

			for i, enc := range vector.Encryptions {
				name := fmt.Sprintf("encryption %d", i)
				t.Run(name, func(t *testing.T) {
					expectedNonce := mustDecodeHex(t, enc.Nonce)
					computedNonce := sender.nextNonce()
					if !bytes.Equal(computedNonce, expectedNonce) {
						t.Errorf("unexpected nonce: got %x, want %x", computedNonce, expectedNonce)
					}

					expectedCiphertext := mustDecodeHex(t, enc.Ct)
					ciphertext, err := sender.Seal(mustDecodeHex(t, enc.Aad), mustDecodeHex(t, enc.Pt))
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(ciphertext, expectedCiphertext) {
						t.Errorf("unexpected ciphertext: got %x want %x", ciphertext, expectedCiphertext)
					}

					expectedPlaintext := mustDecodeHex(t, enc.Pt)
					plaintext, err := recipient.Open(mustDecodeHex(t, enc.Aad), mustDecodeHex(t, enc.Ct))
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

func parsePublicKey(t *testing.T, kemID uint16, keyBytes []byte) (*ecdh.PublicKey, *mlkem.EncapsulationKey768) {
	switch kemID {
	case 0x0010: // DHKEM(P-256, HKDF-SHA256)
		k, err := ecdh.P256().NewPublicKey(keyBytes)
		if err != nil {
			t.Fatal(err)
		}
		return k, nil
	case 0x0050: // QSF-P256-MLKEM768-SHAKE256-SHA3256
		pq, err := mlkem.NewEncapsulationKey768(keyBytes[:mlkem.EncapsulationKeySize768])
		if err != nil {
			t.Fatal(err)
		}
		k, err := ecdh.P256().NewPublicKey(keyBytes[mlkem.EncapsulationKeySize768:])
		if err != nil {
			t.Fatal(err)
		}
		return k, pq
	case 0x647a: // QSF-X25519-MLKEM768-SHAKE256-SHA3256
		pq, err := mlkem.NewEncapsulationKey768(keyBytes[:mlkem.EncapsulationKeySize768])
		if err != nil {
			t.Fatal(err)
		}
		k, err := ecdh.X25519().NewPublicKey(keyBytes[mlkem.EncapsulationKeySize768:])
		if err != nil {
			t.Fatal(err)
		}
		return k, pq
	default:
		t.Fatalf("unsupported KEM %04x", kemID)
		panic("unreachable")
	}
}

func p256KeyFromSeedQSF(t *testing.T, seed []byte) *ecdh.PrivateKey {
	t.Helper()
	if len(seed) != 48 {
		t.Fatalf("invalid seed length %d, expected 48", len(seed))
	}
	s := new(big.Int).Mod(new(big.Int).SetBytes(seed), elliptic.P256().Params().P)
	sb := make([]byte, 32)
	s.FillBytes(sb)
	k, err := ecdh.P256().NewPrivateKey(sb)
	if err != nil {
		t.Fatalf("failed to create P-256 private key: %v", err)
	}
	return k
}

func p256KeyFromSeedDHKEM(t *testing.T, seed []byte, kdf KDF, suiteID []byte) *ecdh.PrivateKey {
	// RFC 9180, Section 7.1.3. Only for testing, without rejection handling.
	t.Helper()
	if len(seed) != 32 {
		t.Fatalf("invalid seed length %d, expected 32", len(seed))
	}
	prk, err := kdf.LabeledExtract(suiteID, nil, "dkp_prk", seed)
	if err != nil {
		t.Fatalf("failed to extract PRK: %v", err)
	}
	s, err := kdf.LabeledExpand(suiteID, prk, "candidate", []byte{0x00}, 32)
	if err != nil {
		t.Fatalf("failed to expand candidate: %v", err)
	}
	k, err := ecdh.P256().NewPrivateKey(s)
	if err != nil {
		t.Fatalf("failed to create P-256 private key: %v", err)
	}
	return k
}

func setupEncapDerand(t *testing.T, kemID uint16, randBytes []byte, pubPQ *mlkem.EncapsulationKey768, kdf KDF) {
	switch kemID {
	case 0x0010: // DHKEM(P-256, HKDF-SHA256)
		suiteID := binary.BigEndian.AppendUint16([]byte("KEM"), kemID)
		k := p256KeyFromSeedDHKEM(t, randBytes, kdf, suiteID)
		testingOnlyGenerateKey = func() *ecdh.PrivateKey { return k }
		t.Cleanup(func() { testingOnlyGenerateKey = nil })
	case 0x0050: // QSF-P256-MLKEM768-SHAKE256-SHA3256
		pqRand, tRand := randBytes[:32], randBytes[32:]
		k := p256KeyFromSeedQSF(t, tRand)
		testingOnlyGenerateKey = func() *ecdh.PrivateKey { return k }
		t.Cleanup(func() { testingOnlyGenerateKey = nil })
		testingOnlyEncapsulate = func() ([]byte, []byte) {
			ct, ss, err := mlkem768.EncapsulateDerand(pubPQ.Bytes(), pqRand)
			if err != nil {
				t.Fatal(err)
			}
			return ss, ct
		}
		t.Cleanup(func() { testingOnlyEncapsulate = nil })
	case 0x647a: // QSF-X25519-MLKEM768-SHAKE256-SHA3256
		pqRand, tRand := randBytes[:32], randBytes[32:]
		k, err := ecdh.X25519().NewPrivateKey(tRand)
		if err != nil {
			t.Fatal(err)
		}
		testingOnlyGenerateKey = func() *ecdh.PrivateKey { return k }
		t.Cleanup(func() { testingOnlyGenerateKey = nil })
		testingOnlyEncapsulate = func() ([]byte, []byte) {
			ct, ss, err := mlkem768.EncapsulateDerand(pubPQ.Bytes(), pqRand)
			if err != nil {
				t.Fatal(err)
			}
			return ss, ct
		}
		t.Cleanup(func() { testingOnlyEncapsulate = nil })
	default:
		t.Fatal("unsupported KEM")
	}
}

func parsePrivateKey(t *testing.T, kemID uint16, keyBytes []byte) (*ecdh.PrivateKey, *mlkem.DecapsulationKey768) {
	switch kemID {
	case 0x0010: // DHKEM(P-256, HKDF-SHA256)
		k, err := ecdh.P256().NewPrivateKey(keyBytes)
		if err != nil {
			t.Fatal(err)
		}
		return k, nil
	case 0x0050: // QSF-P256-MLKEM768-SHAKE256-SHA3256
		s := sha3.NewSHAKE256()
		s.Write(keyBytes)
		exp := make([]byte, mlkem.SeedSize+48)
		s.Read(exp)

		pq, err := mlkem.NewDecapsulationKey768(exp[:mlkem.SeedSize])
		if err != nil {
			t.Fatal(err)
		}
		k := p256KeyFromSeedQSF(t, exp[mlkem.SeedSize:])
		return k, pq
	case 0x647a: // QSF-X25519-MLKEM768-SHAKE256-SHA3256
		s := sha3.NewSHAKE256()
		s.Write(keyBytes)
		exp := make([]byte, mlkem.SeedSize+32)
		s.Read(exp)

		pq, err := mlkem.NewDecapsulationKey768(exp[:mlkem.SeedSize])
		if err != nil {
			t.Fatal(err)
		}
		k, err := ecdh.X25519().NewPrivateKey(exp[mlkem.SeedSize:])
		if err != nil {
			t.Fatal(err)
		}
		return k, pq
	default:
		t.Fatalf("unsupported KEM %04x", kemID)
		panic("unreachable")
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
