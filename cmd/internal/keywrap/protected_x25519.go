package keywrap

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"

	"filippo.io/age/cmd/internal/passphrase"
	"filippo.io/age/internal/age"
	"filippo.io/age/internal/format"
	"golang.org/x/crypto/scrypt"
)

// ProtectedX25519Identity is a X25519Identity with password-protected private key
type ProtectedX25519Identity struct {
	password, prefixedProtectedSecretKey []byte
	*age.X25519Identity
}

// NOTE: keeping the type to be X25519 to share the X25519Recipient matching
func (*ProtectedX25519Identity) Type() string { return "X25519" }

func NewProtectedX25519Identity(secretKey []byte, password []byte) (*ProtectedX25519Identity, error) {
	i, err := age.NewX25519Identity(secretKey)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, SCRYPT_PARAM_SALT_BYTES)
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, fmt.Errorf("Fail to read random bytes for salt: %v", err)
	}
	// get derived key from password and plaintext salt
	dk, err := scrypt.Key(password, salt, SCRYPT_PARAM_N, SCRPYT_PARAM_R, SCRPYT_PARAM_P, SCRPYT_PARAM_BYTES)
	if err != nil {
		return nil, fmt.Errorf("Fail to get derived key from scrypt: %v", err)
	}
	// deduce the protected/encrypted secret key
	protectedSecretKey := make([]byte, SCRPYT_PARAM_BYTES)
	_, err = xorBytes(protectedSecretKey, dk, secretKey)
	if err != nil {
		return nil, fmt.Errorf("Fail to encrypt secret key: %v", err)
	}

	// prefixProtectedSecretKey := salt || protectedSecretKey
	prefixedProtectedSecretKey := make([]byte, 0)
	prefixedProtectedSecretKey = append(prefixedProtectedSecretKey, salt...)
	prefixedProtectedSecretKey = append(prefixedProtectedSecretKey, protectedSecretKey...)

	return &ProtectedX25519Identity{password, prefixedProtectedSecretKey, i}, nil
}

// GenerateProtectedX25519Identity generates a fresh ProtectedX25519Identity
func GenerateProtectedX25519Identity() (*ProtectedX25519Identity, error) {
	pass, err := passphrase.PromptForEncryption()
	if err != nil {
		return nil, err
	}
	i, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("internal error: %v", err)
	}
	return NewProtectedX25519Identity(i.GetSecretKey(), pass)
}

// ParseProtectedX25519Identity returns a new X25519Recipient from a Bech32 protected private key
// encoding with the "AGE-PROTECTED_SECRET-KEY" prefix.
func ParseProtectedX25519Identity(s string) (*ProtectedX25519Identity, error) {
	re := regexp.MustCompile(`^AGE-PROTECTED-SECRET-KEY-(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)
	if !re.Match([]byte(s)) {
		return nil, fmt.Errorf("malformed protected secret key %q", s)
	}
	k, err := base64.StdEncoding.DecodeString(s[len(KEY_PREFIX):])
	if err != nil {
		return nil, fmt.Errorf("malformed protected secret key %q, %v", s, err)
	}

	// FIXME: print out the filename before interative prompt, otherwise confusing for multiple key files
	pass, err := passphrase.PromptForDecryption()
	if err != nil {
		return nil, fmt.Errorf("fail to get password: %v", err)
	}

	salt := k[:SCRYPT_PARAM_SALT_BYTES]
	protectedSecretKey := k[SCRYPT_PARAM_SALT_BYTES:]
	// get derived key from password and plaintext salt
	dk, err := scrypt.Key(pass, salt, SCRYPT_PARAM_N, SCRPYT_PARAM_R, SCRPYT_PARAM_P, SCRPYT_PARAM_BYTES)
	if err != nil {
		return nil, err
	}
	// deduce the unprotected/unencrypted secret key
	sk := make([]byte, SCRPYT_PARAM_BYTES)
	_, err = xorBytes(sk, dk, protectedSecretKey)
	if err != nil {
		return nil, fmt.Errorf("Fail to decrypt protected secret key, internal error: %v", err)
	}

	i, err := age.NewX25519Identity(sk)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key %q: %v", sk, err)
	}
	return &ProtectedX25519Identity{pass, k, i}, nil
}

func (p *ProtectedX25519Identity) Unwrap(block *format.Recipient) ([]byte, error) {
	if block.Type != "X25519" {
		return nil, age.ErrIncorrectIdentity
	}
	return p.X25519Identity.Unwrap(block)
}

// Recipient returns the public X25519Recipient value corresponding to the identity.
func (p *ProtectedX25519Identity) Recipient() *age.X25519Recipient {
	return p.X25519Identity.Recipient()
}

// String returns the Bech32 encoding of identity's protected private key.
func (p *ProtectedX25519Identity) String() string {
	encoded := base64.StdEncoding.EncodeToString(p.prefixedProtectedSecretKey)
	return KEY_PREFIX + encoded
}

func xorBytes(dst, a, b []byte) (int, error) {
	n := len(a)
	if len(b) != n {
		return 0, fmt.Errorf("XOR only supports two equal length bytes")
	}
	if cap(dst) < n {
		return 0, fmt.Errorf("Not enough capacity for dst of XOR operation")
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n, nil
}
