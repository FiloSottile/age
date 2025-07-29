package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// Age extension message formats for SSH agent communication

// RSADecryptionRequest represents an RSA-OAEP decryption request
type RSADecryptionRequest struct {
	PublicKeyFingerprint [4]byte // 4-byte SHA256 hash of SSH public key
	EncryptedFileKey     []byte  // RSA-OAEP encrypted file key
	Label                string  // OAEP label ("age-encryption.org/v1/ssh-rsa")
}

// Ed25519DecryptionRequest represents an Ed25519/X25519 key agreement request  
type Ed25519DecryptionRequest struct {
	PublicKeyFingerprint [4]byte // 4-byte SHA256 hash of SSH public key
	EphemeralPublicKey   [32]byte // Ephemeral Curve25519 public key
	EncryptedFileKey     []byte   // ChaCha20-Poly1305 encrypted file key
}

// DecryptionResponse represents a successful decryption response
type DecryptionResponse struct {
	FileKey []byte // Decrypted 16-byte file key
}

// ParseAgeStanza parses an age stanza into a decryption request
func ParseAgeStanza(stanzaType string, args []string, body []byte) (interface{}, error) {
	switch stanzaType {
	case "ssh-rsa":
		return parseRSAStanza(args, body)
	case "ssh-ed25519":
		return parseEd25519Stanza(args, body)
	default:
		return nil, fmt.Errorf("unsupported stanza type: %s", stanzaType)
	}
}

func parseRSAStanza(args []string, body []byte) (*RSADecryptionRequest, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("ssh-rsa stanza requires exactly 1 argument, got %d", len(args))
	}

	// Decode fingerprint from base64
	fingerprintBytes, err := base64.RawStdEncoding.Strict().DecodeString(args[0])
	if err != nil {
		return nil, fmt.Errorf("decoding fingerprint: %v", err)
	}

	if len(fingerprintBytes) != 4 {
		return nil, fmt.Errorf("fingerprint must be 4 bytes, got %d", len(fingerprintBytes))
	}

	var fingerprint [4]byte
	copy(fingerprint[:], fingerprintBytes)

	return &RSADecryptionRequest{
		PublicKeyFingerprint: fingerprint,
		EncryptedFileKey:     body,
		Label:                "age-encryption.org/v1/ssh-rsa",
	}, nil
}

func parseEd25519Stanza(args []string, body []byte) (*Ed25519DecryptionRequest, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("ssh-ed25519 stanza requires exactly 2 arguments, got %d", len(args))
	}

	// Decode fingerprint from base64
	fingerprintBytes, err := base64.RawStdEncoding.Strict().DecodeString(args[0])
	if err != nil {
		return nil, fmt.Errorf("decoding fingerprint: %v", err)
	}

	if len(fingerprintBytes) != 4 {
		return nil, fmt.Errorf("fingerprint must be 4 bytes, got %d", len(fingerprintBytes))
	}

	// Decode ephemeral public key from base64
	ephemeralBytes, err := base64.RawStdEncoding.Strict().DecodeString(args[1])
	if err != nil {
		return nil, fmt.Errorf("decoding ephemeral public key: %v", err)
	}

	if len(ephemeralBytes) != 32 {
		return nil, fmt.Errorf("ephemeral public key must be 32 bytes, got %d", len(ephemeralBytes))
	}

	var fingerprint [4]byte
	var ephemeralPubKey [32]byte
	copy(fingerprint[:], fingerprintBytes)
	copy(ephemeralPubKey[:], ephemeralBytes)

	return &Ed25519DecryptionRequest{
		PublicKeyFingerprint: fingerprint,
		EphemeralPublicKey:   ephemeralPubKey,
		EncryptedFileKey:     body,
	}, nil
}

// MarshalRSADecryptionRequest marshals an RSA decryption request for SSH agent extension
func MarshalRSADecryptionRequest(req *RSADecryptionRequest) ([]byte, error) {
	// Binary format:
	// 4 bytes: fingerprint
	// 4 bytes: label length
	// N bytes: label string
	// 4 bytes: encrypted file key length
	// N bytes: encrypted file key

	labelBytes := []byte(req.Label)
	totalLen := 4 + 4 + len(labelBytes) + 4 + len(req.EncryptedFileKey)
	
	payload := make([]byte, 0, totalLen)
	
	// Fingerprint
	payload = append(payload, req.PublicKeyFingerprint[:]...)
	
	// Label
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(labelBytes)))
	payload = append(payload, lenBytes...)
	payload = append(payload, labelBytes...)
	
	// Encrypted file key
	binary.BigEndian.PutUint32(lenBytes, uint32(len(req.EncryptedFileKey)))
	payload = append(payload, lenBytes...)
	payload = append(payload, req.EncryptedFileKey...)
	
	return payload, nil
}

// MarshalEd25519DecryptionRequest marshals an Ed25519 decryption request for SSH agent extension
func MarshalEd25519DecryptionRequest(req *Ed25519DecryptionRequest) ([]byte, error) {
	// Binary format:
	// 4 bytes: fingerprint
	// 32 bytes: ephemeral public key
	// 4 bytes: encrypted file key length
	// N bytes: encrypted file key

	totalLen := 4 + 32 + 4 + len(req.EncryptedFileKey)
	payload := make([]byte, 0, totalLen)
	
	// Fingerprint
	payload = append(payload, req.PublicKeyFingerprint[:]...)
	
	// Ephemeral public key
	payload = append(payload, req.EphemeralPublicKey[:]...)
	
	// Encrypted file key
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(req.EncryptedFileKey)))
	payload = append(payload, lenBytes...)
	payload = append(payload, req.EncryptedFileKey...)
	
	return payload, nil
}

// UnmarshalDecryptionResponse unmarshals a decryption response from SSH agent extension
func UnmarshalDecryptionResponse(data []byte) (*DecryptionResponse, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("response too short")
	}
	
	// Binary format:
	// 4 bytes: file key length
	// N bytes: file key (should be 16 bytes)
	
	keyLen := binary.BigEndian.Uint32(data[:4])
	if len(data) < int(4+keyLen) {
		return nil, fmt.Errorf("invalid response length")
	}
	
	if keyLen != 16 {
		return nil, fmt.Errorf("file key must be 16 bytes, got %d", keyLen)
	}
	
	fileKey := make([]byte, keyLen)
	copy(fileKey, data[4:4+keyLen])
	
	return &DecryptionResponse{
		FileKey: fileKey,
	}, nil
}