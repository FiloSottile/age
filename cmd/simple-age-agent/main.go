package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	extensionAgeDecryptRSA     = "age-decrypt-rsa@filippo.io"
	extensionAgeDecryptEd25519 = "age-decrypt-ed25519@filippo.io"
)

// SimpleAgeAgent is a minimal SSH agent that can perform age decryption
type SimpleAgeAgent struct {
	keys []StoredKey
}

type StoredKey struct {
	PublicKey  ssh.PublicKey
	PrivateKey interface{} // *rsa.PrivateKey or ed25519.PrivateKey
	Comment    string
}

func NewSimpleAgeAgent() *SimpleAgeAgent {
	return &SimpleAgeAgent{
		keys: make([]StoredKey, 0),
	}
}

// Generate some test keys for demonstration
func (a *SimpleAgeAgent) GenerateTestKeys() error {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating RSA key: %v", err)
	}
	
	rsaPubKey, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return fmt.Errorf("creating RSA public key: %v", err)
	}

	a.keys = append(a.keys, StoredKey{
		PublicKey:  rsaPubKey,
		PrivateKey: rsaKey,
		Comment:    "test-rsa-key",
	})

	// Generate Ed25519 key
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating Ed25519 key: %v", err)
	}

	ed25519PubKey, err := ssh.NewPublicKey(ed25519Key.Public())
	if err != nil {
		return fmt.Errorf("creating Ed25519 public key: %v", err)
	}

	a.keys = append(a.keys, StoredKey{
		PublicKey:  ed25519PubKey,
		PrivateKey: ed25519Key,
		Comment:    "test-ed25519-key",
	})

	fmt.Fprintf(os.Stderr, "Generated %d test keys\n", len(a.keys))
	return nil
}

// Implement agent.Agent interface
func (a *SimpleAgeAgent) List() ([]*agent.Key, error) {
	var keys []*agent.Key
	for _, key := range a.keys {
		keys = append(keys, &agent.Key{
			Format:  key.PublicKey.Type(),
			Blob:    key.PublicKey.Marshal(),
			Comment: key.Comment,
		})
	}
	return keys, nil
}

func (a *SimpleAgeAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return nil, fmt.Errorf("signing not implemented in demo agent")
}

func (a *SimpleAgeAgent) Add(key agent.AddedKey) error {
	return fmt.Errorf("add not implemented in demo agent")
}

func (a *SimpleAgeAgent) Remove(key ssh.PublicKey) error {
	return fmt.Errorf("remove not implemented in demo agent")
}

func (a *SimpleAgeAgent) RemoveAll() error {
	return fmt.Errorf("remove all not implemented in demo agent")
}

func (a *SimpleAgeAgent) Lock(passphrase []byte) error {
	return fmt.Errorf("lock not implemented in demo agent")
}

func (a *SimpleAgeAgent) Unlock(passphrase []byte) error {
	return fmt.Errorf("unlock not implemented in demo agent")
}

func (a *SimpleAgeAgent) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("signers not implemented in demo agent")
}

// Implement agent.ExtendedAgent interface
func (a *SimpleAgeAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	switch extensionType {
	case extensionAgeDecryptRSA:
		return a.handleRSADecryption(contents)
	case extensionAgeDecryptEd25519:
		return a.handleEd25519Decryption(contents)
	default:
		return nil, agent.ErrExtensionUnsupported
	}
}

func (a *SimpleAgeAgent) handleRSADecryption(payload []byte) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "DEBUG: handling RSA decryption request\n")

	req, err := unmarshalRSADecryptionRequest(payload)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling RSA request: %v", err)
	}

	// Find matching RSA key
	for _, key := range a.keys {
		if key.PublicKey.Type() != "ssh-rsa" {
			continue
		}

		keyFingerprint := computeSSHFingerprint(key.PublicKey)
		if keyFingerprint != req.PublicKeyFingerprint {
			continue
		}

		fmt.Fprintf(os.Stderr, "DEBUG: found matching RSA key\n")

		rsaKey, ok := key.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA private key")
		}

		// Perform RSA-OAEP decryption
		fileKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, req.EncryptedFileKey, []byte(req.Label))
		if err != nil {
			return nil, fmt.Errorf("RSA-OAEP decryption failed: %v", err)
		}

		fmt.Fprintf(os.Stderr, "DEBUG: RSA decryption successful, file key length: %d\n", len(fileKey))
		return marshalDecryptionResponse(fileKey), nil
	}

	return nil, fmt.Errorf("no matching RSA key found")
}

func (a *SimpleAgeAgent) handleEd25519Decryption(payload []byte) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "DEBUG: handling Ed25519 decryption request\n")

	req, err := unmarshalEd25519DecryptionRequest(payload)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling Ed25519 request: %v", err)
	}

	// Find matching Ed25519 key
	for _, key := range a.keys {
		if key.PublicKey.Type() != "ssh-ed25519" {
			continue
		}

		keyFingerprint := computeSSHFingerprint(key.PublicKey)
		if keyFingerprint != req.PublicKeyFingerprint {
			continue
		}

		fmt.Fprintf(os.Stderr, "DEBUG: found matching Ed25519 key\n")

		ed25519Key, ok := key.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not Ed25519 private key")
		}

		// Convert Ed25519 to Curve25519 private key
		var curve25519Private [32]byte
		copy(curve25519Private[:], ed25519Key.Seed())

		// Perform X25519 key agreement with ephemeral public key
		sharedSecret, err := curve25519.X25519(curve25519Private[:], req.EphemeralPublicKey[:])
		if err != nil {
			return nil, fmt.Errorf("X25519 key agreement failed: %v", err)
		}

		// Derive tweak using HKDF
		tweak := make([]byte, 32)
		info := key.PublicKey.Marshal()
		hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, append(info, []byte("age-encryption.org/v1/ssh-ed25519")...))
		if _, err := io.ReadFull(hkdfReader, tweak); err != nil {
			return nil, fmt.Errorf("deriving tweak: %v", err)
		}

		// Apply tweak to shared secret  
		tweakedSecret, err := curve25519.X25519(tweak, sharedSecret)
		if err != nil {
			return nil, fmt.Errorf("applying tweak: %v", err)
		}

		// Derive wrapping key
		var curve25519Public [32]byte
		curve25519.ScalarBaseMult(&curve25519Public, &curve25519Private)
		salt := append(req.EphemeralPublicKey[:], curve25519Public[:]...)
		
		wrappingKey := make([]byte, 32)
		hkdfReader = hkdf.New(sha256.New, tweakedSecret, salt, []byte("age-encryption.org/v1/ssh-ed25519"))
		if _, err := io.ReadFull(hkdfReader, wrappingKey); err != nil {
			return nil, fmt.Errorf("deriving wrapping key: %v", err)
		}

		// Decrypt using ChaCha20-Poly1305
		aead, err := chacha20poly1305.New(wrappingKey)
		if err != nil {
			return nil, fmt.Errorf("creating AEAD: %v", err)
		}

		nonce := make([]byte, aead.NonceSize()) // Zero nonce
		fileKey, err := aead.Open(nil, nonce, req.EncryptedFileKey, nil)
		if err != nil {
			return nil, fmt.Errorf("ChaCha20-Poly1305 decryption failed: %v", err)
		}

		fmt.Fprintf(os.Stderr, "DEBUG: Ed25519 decryption successful, file key length: %d\n", len(fileKey))
		return marshalDecryptionResponse(fileKey), nil
	}

	return nil, fmt.Errorf("no matching Ed25519 key found")
}

// Protocol message structures and marshaling
type RSADecryptionRequest struct {
	PublicKeyFingerprint [4]byte
	Label                string
	EncryptedFileKey     []byte
}

type Ed25519DecryptionRequest struct {
	PublicKeyFingerprint [4]byte
	EphemeralPublicKey   [32]byte
	EncryptedFileKey     []byte
}

func unmarshalRSADecryptionRequest(data []byte) (*RSADecryptionRequest, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("RSA request too short")
	}

	req := &RSADecryptionRequest{}
	offset := 0

	copy(req.PublicKeyFingerprint[:], data[offset:offset+4])
	offset += 4

	labelLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if len(data) < offset+int(labelLen) {
		return nil, fmt.Errorf("invalid label length")
	}
	req.Label = string(data[offset : offset+int(labelLen)])
	offset += int(labelLen)

	keyLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if len(data) < offset+int(keyLen) {
		return nil, fmt.Errorf("invalid encrypted key length")
	}
	req.EncryptedFileKey = make([]byte, keyLen)
	copy(req.EncryptedFileKey, data[offset:offset+int(keyLen)])

	return req, nil
}

func unmarshalEd25519DecryptionRequest(data []byte) (*Ed25519DecryptionRequest, error) {
	if len(data) < 40 {
		return nil, fmt.Errorf("Ed25519 request too short")
	}

	req := &Ed25519DecryptionRequest{}
	offset := 0

	copy(req.PublicKeyFingerprint[:], data[offset:offset+4])
	offset += 4

	copy(req.EphemeralPublicKey[:], data[offset:offset+32])
	offset += 32

	keyLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	if len(data) < offset+int(keyLen) {
		return nil, fmt.Errorf("invalid encrypted key length")
	}
	req.EncryptedFileKey = make([]byte, keyLen)
	copy(req.EncryptedFileKey, data[offset:offset+int(keyLen)])

	return req, nil
}

func computeSSHFingerprint(pubKey ssh.PublicKey) [4]byte {
	hash := sha256.Sum256(pubKey.Marshal())
	var fingerprint [4]byte
	copy(fingerprint[:], hash[:4])
	return fingerprint
}

func marshalDecryptionResponse(fileKey []byte) []byte {
	response := make([]byte, 4+len(fileKey))
	binary.BigEndian.PutUint32(response[:4], uint32(len(fileKey)))
	copy(response[4:], fileKey)
	return response
}

func main() {
	socketPath := "/tmp/simple-age-agent.sock"
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to listen on socket: %v", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	ageAgent := NewSimpleAgeAgent()
	if err := ageAgent.GenerateTestKeys(); err != nil {
		log.Fatalf("Failed to generate test keys: %v", err)
	}

	fmt.Printf("Simple Age SSH Agent listening on %s\n", socketPath)
	fmt.Printf("Set SSH_AUTH_SOCK=%s to use this agent\n", socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()
			if err := agent.ServeAgent(ageAgent, conn); err != nil && err != io.EOF {
				log.Printf("Agent connection error: %v", err)
			}
		}(conn)
	}
}