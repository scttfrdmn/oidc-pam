package security

import (
	"encoding/base64"
	"testing"
)

// TestNewEncryptionRequiresBase64Key covers the Option B breaking change: the
// key must be a base64-encoded 32-byte value, used directly (no PBKDF2).
func TestNewEncryptionRequiresBase64Key(t *testing.T) {
	// A freshly generated key must be accepted.
	good, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := NewEncryption(good); err != nil {
		t.Errorf("GenerateKey output should be accepted, got: %v", err)
	}

	// Raw (unpadded) base64 of 32 bytes should also work.
	raw := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	if _, err := NewEncryption(raw); err != nil {
		t.Errorf("raw base64 32-byte key should be accepted, got: %v", err)
	}

	bad := []struct {
		name, key string
	}{
		{"passphrase", "this-is-a-passphrase-not-a-key!!"},
		{"too short (base64 of 16 bytes)", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))},
		{"too long (base64 of 48 bytes)", base64.StdEncoding.EncodeToString(make([]byte, 48))},
		{"not base64", "@@@@not-base64@@@@"},
	}
	for _, tc := range bad {
		if _, err := NewEncryption(tc.key); err == nil {
			t.Errorf("%s: expected rejection, got nil error", tc.name)
		}
		if err := ValidateKeyString(tc.key); err == nil {
			t.Errorf("%s: ValidateKeyString should reject", tc.name)
		}
	}
}

// TestEncryptionDestroyZeroesKey verifies Destroy scrubs the key material.
func TestEncryptionDestroyZeroesKey(t *testing.T) {
	enc, err := NewEncryption(mustKey(t))
	if err != nil {
		t.Fatalf("NewEncryption: %v", err)
	}
	enc.Destroy()
	for i, b := range enc.key {
		if b != 0 {
			t.Fatalf("key byte %d not zeroed after Destroy", i)
		}
	}
}

func mustKey(t *testing.T) string {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}
