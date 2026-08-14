package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// KeyBytes is the required raw key length for AES-256 (32 bytes).
const KeyBytes = 32

// Encryption handles encryption and decryption of sensitive data
type Encryption struct {
	key []byte
}

// NewEncryption creates a new encryption instance.
//
// keyString MUST be a base64-encoded 32-byte (256-bit) key, exactly as produced
// by GenerateKey(). The decoded bytes are used directly as the AES-256-GCM key —
// no password-based derivation is performed, so the key must already be full
// entropy. A passphrase, short string, or wrong-length key is rejected.
//
// BREAKING CHANGE (v0.4.0): earlier versions accepted an arbitrary passphrase
// and stretched it with PBKDF2 + a static salt. Operators must now supply a
// machine-generated key (see `oidc-admin`/GenerateKey). The static-salt
// derivation has been removed.
func NewEncryption(keyString string) (*Encryption, error) {
	if keyString == "" {
		return nil, fmt.Errorf("encryption key cannot be empty")
	}

	key, err := decodeKey(keyString)
	if err != nil {
		return nil, err
	}

	return &Encryption{
		key: key,
	}, nil
}

// decodeKey base64-decodes keyString and validates it is exactly KeyBytes long.
// It accepts both standard and raw (unpadded) base64 for operator convenience.
func decodeKey(keyString string) ([]byte, error) {
	var key []byte
	var err error
	if key, err = base64.StdEncoding.DecodeString(keyString); err != nil {
		if key, err = base64.RawStdEncoding.DecodeString(keyString); err != nil {
			return nil, fmt.Errorf("encryption key must be base64-encoded: %w", err)
		}
	}
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("encryption key must decode to exactly %d bytes, got %d (generate one with `oidc-admin` or GenerateKey)", KeyBytes, len(key))
	}
	return key, nil
}

// ValidateKeyString reports whether keyString is a valid base64-encoded 32-byte
// key, without constructing an Encryption. Used by config validation so a bad
// key is caught at startup rather than first use.
func ValidateKeyString(keyString string) error {
	_, err := decodeKey(keyString)
	return err
}

// Encrypt encrypts the given plaintext with no additional authenticated data.
//
// Prefer EncryptWithAAD wherever the ciphertext will be stored in a record that
// identifies something: GCM proves a ciphertext was not modified, but on its own
// it says nothing about where the ciphertext belongs, so one lifted out of a
// record and pasted into another still decrypts (#232).
func (e *Encryption) Encrypt(plaintext string) (string, error) {
	return e.EncryptWithAAD(plaintext, nil)
}

// EncryptWithAAD encrypts plaintext and binds the ciphertext to aad, which is
// authenticated but not stored: decryption succeeds only when the caller supplies
// the same bytes. Pass whatever identifies the record the ciphertext is being
// written into, so that moving it to another record makes it undecryptable rather
// than making it somebody else's secret.
func (e *Encryption) EncryptWithAAD(plaintext string, aad []byte) (string, error) {
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
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), aad)

	// Encode to base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a ciphertext that was encrypted with no additional
// authenticated data.
func (e *Encryption) Decrypt(ciphertext string) (string, error) {
	return e.DecryptWithAAD(ciphertext, nil)
}

// DecryptWithAAD decrypts a ciphertext produced by EncryptWithAAD, and fails
// unless aad is byte-identical to the value it was encrypted under. The error
// deliberately does not distinguish a wrong AAD from a corrupted ciphertext:
// both mean the record and the secret in it do not belong together.
func (e *Encryption) DecryptWithAAD(ciphertext string, aad []byte) (string, error) {
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
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, aad)
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
