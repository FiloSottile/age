package age

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"github.com/FiloSottile/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func aeadEncrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func aeadDecrypt(key, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Open(nil, nonce, ciphertext, nil)
}

func headerMAC(fileKey []byte, hdr *format.Header) ([]byte, error) {
	h := hkdf.New(sha256.New, fileKey, nil, []byte("header"))
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(h, hmacKey); err != nil {
		return nil, err
	}
	hh := hmac.New(sha256.New, hmacKey)
	if err := hdr.MarshalWithoutMAC(hh); err != nil {
		return nil, err
	}
	return hh.Sum(nil), nil
}

func streamKey(fileKey, nonce []byte) []byte {
	h := hkdf.New(sha256.New, fileKey, nonce, []byte("payload"))
	streamKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, streamKey); err != nil {
		panic("age: internal error: failed to read from HKDF: " + err.Error())
	}
	return streamKey
}
