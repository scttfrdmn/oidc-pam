package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// Encryption handles encryption and decryption of sensitive data
type Encryption struct {
	key []byte
}

// NewEncryption creates a new encryption instance.
//
// The 32-byte AES key is derived from keyString using PBKDF2-HMAC-SHA256
// (600,000 iterations) with a fixed application-level salt. keyString is
// expected to be a high-entropy secret — config validation requires 32+ bytes,
// and GenerateKey() produces a suitable base64 value. The static salt is an
// accepted trade-off given that assumption; its purpose is computational cost
// against brute force, not per-deployment uniqueness.
func NewEncryption(keyString string) (*Encryption, error) {
	if keyString == "" {
		return nil, fmt.Errorf("encryption key cannot be empty")
	}

	salt := []byte("oidc-pam-token-encryption-v1")
	key := pbkdf2.Key([]byte(keyString), salt, 600000, 32, sha256.New)

	return &Encryption{
		key: key,
	}, nil
}

// Encrypt encrypts the given plaintext
func (e *Encryption) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	// Create cipher block
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Encode to base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext
func (e *Encryption) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Decode from base64
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Create cipher block
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum length
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	// Best-effort: zero the transient plaintext buffer after copying to a string.
	// Go strings are immutable and may be copied by the GC, so this cannot fully
	// scrub the secret, but it minimizes the window the raw bytes live in the heap
	// buffer we control (L-16).
	out := string(plaintext)
	Zero(plaintext)
	return out, nil
}

// Zero overwrites b with zeros. Used to scrub key material and transient
// plaintext buffers (L-16). Note: this cannot scrub data already copied into Go
// strings, which are immutable.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Destroy zeroes the derived encryption key. After Destroy the Encryption value
// must not be used again. Call when the broker shuts down to limit how long key
// material persists in memory (L-16).
func (e *Encryption) Destroy() {
	Zero(e.key)
}

// EncryptBytes encrypts the given byte slice
func (e *Encryption) EncryptBytes(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}

	// Create cipher block
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// DecryptBytes decrypts the given byte slice
func (e *Encryption) DecryptBytes(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, nil
	}

	// Create cipher block
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum length
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// GenerateNonce generates a cryptographically random URL-safe nonce string.
// Returns 32 random bytes, base64url-encoded (no padding).
func GenerateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateKey generates a new encryption key
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(key), nil
}
