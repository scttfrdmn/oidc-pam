package security

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewEncryption(t *testing.T) {
	// Test with valid key
	enc, err := NewEncryption("test-key")
	if err != nil {
		t.Fatalf("Failed to create encryption: %v", err)
	}
	if enc == nil {
		t.Error("Expected non-nil encryption")
	}

	// Test with empty key
	_, err = NewEncryption("")
	if err == nil {
		t.Error("Expected error with empty key")
	}
	if !strings.Contains(err.Error(), "encryption key cannot be empty") {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	enc, err := NewEncryption("test-key-for-encryption")
	if err != nil {
		t.Fatalf("Failed to create encryption: %v", err)
	}

	testCases := []string{
		"hello world",
		"sensitive data",
		"",
		"special characters: 🔐💻🛡️",
		"long string: " + strings.Repeat("a", 1000),
		"json: {\"key\":\"value\",\"number\":123}",
		"newlines\nand\ttabs",
	}

	for _, plaintext := range testCases {
		t.Run("plaintext_"+plaintext[:min(len(plaintext), 20)], func(t *testing.T) {
			// Encrypt
			ciphertext, err := enc.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			// For empty string, should return empty
			if plaintext == "" {
				if ciphertext != "" {
					t.Error("Expected empty ciphertext for empty plaintext")
				}
				return
			}

			// Ciphertext should be different from plaintext
			if ciphertext == plaintext {
				t.Error("Ciphertext should be different from plaintext")
			}

			// Decrypt
			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Failed to decrypt: %v", err)
			}

			// Should match original
			if decrypted != plaintext {
				t.Errorf("Decrypted text doesn't match original. Expected: %s, Got: %s", plaintext, decrypted)
			}
		})
	}
}

func TestEncryptDecryptBytes(t *testing.T) {
	enc, err := NewEncryption("test-key-for-bytes")
	if err != nil {
		t.Fatalf("Failed to create encryption: %v", err)
	}

	testCases := [][]byte{
		[]byte("hello world"),
		[]byte("binary data"),
		[]byte{0x00, 0x01, 0x02, 0xFF},
		nil,
		[]byte(""),
		make([]byte, 1000), // zeros
	}

	for i, plaintext := range testCases {
		t.Run("bytes_case_"+string(rune(i+'A')), func(t *testing.T) {
			// Encrypt
			ciphertext, err := enc.EncryptBytes(plaintext)
			if err != nil {
				t.Fatalf("Failed to encrypt bytes: %v", err)
			}

			// For empty/nil input, should return nil
			if len(plaintext) == 0 {
				if ciphertext != nil {
					t.Error("Expected nil ciphertext for empty plaintext")
				}
				return
			}

			// Decrypt
			decrypted, err := enc.DecryptBytes(ciphertext)
			if err != nil {
				t.Fatalf("Failed to decrypt bytes: %v", err)
			}

			// Should match original
			if len(decrypted) != len(plaintext) {
				t.Errorf("Decrypted length doesn't match. Expected: %d, Got: %d", len(plaintext), len(decrypted))
			}

			for j := 0; j < len(plaintext); j++ {
				if decrypted[j] != plaintext[j] {
					t.Errorf("Decrypted bytes don't match at position %d. Expected: %d, Got: %d", j, plaintext[j], decrypted[j])
				}
			}
		})
	}
}

func TestDecryptInvalidData(t *testing.T) {
	enc, err := NewEncryption("test-key")
	if err != nil {
		t.Fatalf("Failed to create encryption: %v", err)
	}

	// Test invalid base64
	_, err = enc.Decrypt("invalid-base64!!!")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	// Test empty string
	result, err := enc.Decrypt("")
	if err != nil {
		t.Errorf("Unexpected error for empty string: %v", err)
	}
	if result != "" {
		t.Error("Expected empty result for empty input")
	}

	// Test too short ciphertext
	shortData := base64.StdEncoding.EncodeToString([]byte("short"))
	_, err = enc.Decrypt(shortData)
	if err == nil {
		t.Error("Expected error for too short ciphertext")
	}
	if !strings.Contains(err.Error(), "ciphertext too short") {
		t.Errorf("Expected specific error message, got: %v", err)
	}

	// Test corrupted ciphertext
	validCiphertext, err := enc.Encrypt("test")
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Corrupt the ciphertext
	data, _ := base64.StdEncoding.DecodeString(validCiphertext)
	data[len(data)-1] ^= 0xFF // flip last byte
	corruptedCiphertext := base64.StdEncoding.EncodeToString(data)

	_, err = enc.Decrypt(corruptedCiphertext)
	if err == nil {
		t.Error("Expected error for corrupted ciphertext")
	}
}

func TestDecryptBytesInvalidData(t *testing.T) {
	enc, err := NewEncryption("test-key")
	if err != nil {
		t.Fatalf("Failed to create encryption: %v", err)
	}

	// Test empty bytes
	result, err := enc.DecryptBytes(nil)
	if err != nil {
		t.Errorf("Unexpected error for nil bytes: %v", err)
	}
	if result != nil {
		t.Error("Expected nil result for nil input")
	}

	// Test too short ciphertext
	shortData := []byte("short")
	_, err = enc.DecryptBytes(shortData)
	if err == nil {
		t.Error("Expected error for too short ciphertext")
	}

	// Test corrupted ciphertext
	validCiphertext, err := enc.EncryptBytes([]byte("test"))
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	// Corrupt the ciphertext
	corruptedCiphertext := make([]byte, len(validCiphertext))
	copy(corruptedCiphertext, validCiphertext)
	corruptedCiphertext[len(corruptedCiphertext)-1] ^= 0xFF // flip last byte

	_, err = enc.DecryptBytes(corruptedCiphertext)
	if err == nil {
		t.Error("Expected error for corrupted ciphertext")
	}
}

func TestGenerateKey(t *testing.T) {
	// Generate multiple keys
	keys := make(map[string]bool)
	for i := 0; i < 10; i++ {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		if key == "" {
			t.Error("Generated key should not be empty")
		}

		// Check if key is unique
		if keys[key] {
			t.Error("Generated key should be unique")
		}
		keys[key] = true

		// Check if key is valid base64
		_, err = base64.StdEncoding.DecodeString(key)
		if err != nil {
			t.Errorf("Generated key should be valid base64: %v", err)
		}

		// Check key length (should be 32 bytes = 44 base64 characters)
		decoded, _ := base64.StdEncoding.DecodeString(key)
		if len(decoded) != 32 {
			t.Errorf("Generated key should be 32 bytes, got %d", len(decoded))
		}
	}
}

func TestEncryptionWithDifferentKeys(t *testing.T) {
	// Create two different encryption instances
	enc1, err := NewEncryption("key1")
	if err != nil {
		t.Fatalf("Failed to create encryption 1: %v", err)
	}

	enc2, err := NewEncryption("key2")
	if err != nil {
		t.Fatalf("Failed to create encryption 2: %v", err)
	}

	plaintext := "test data"

	// Encrypt with first key
	ciphertext1, err := enc1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt with key1: %v", err)
	}

	// Encrypt with second key
	ciphertext2, err := enc2.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt with key2: %v", err)
	}

	// Ciphertexts should be different
	if ciphertext1 == ciphertext2 {
		t.Error("Different keys should produce different ciphertexts")
	}

	// First key should not be able to decrypt second key's ciphertext
	_, err = enc1.Decrypt(ciphertext2)
	if err == nil {
		t.Error("Different keys should not be able to decrypt each other's ciphertext")
	}
}

func TestEncryptionConsistency(t *testing.T) {
	enc, err := NewEncryption("consistent-key")
	if err != nil {
		t.Fatalf("Failed to create encryption: %v", err)
	}

	plaintext := "consistent test data"

	// Encrypt same data multiple times
	for i := 0; i < 5; i++ {
		ciphertext, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt (iteration %d): %v", i, err)
		}

		// Should be able to decrypt
		decrypted, err := enc.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt (iteration %d): %v", i, err)
		}

		if decrypted != plaintext {
			t.Errorf("Decrypted text doesn't match (iteration %d)", i)
		}
	}
}

func TestEncryptionKeyDerivation(t *testing.T) {
	// Same key string should produce same encryption key
	enc1, err := NewEncryption("same-key")
	if err != nil {
		t.Fatalf("Failed to create encryption 1: %v", err)
	}

	enc2, err := NewEncryption("same-key")
	if err != nil {
		t.Fatalf("Failed to create encryption 2: %v", err)
	}

	plaintext := "test data"

	// Encrypt with first instance
	ciphertext, err := enc1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt with second instance
	decrypted, err := enc2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Error("Same key string should produce compatible encryption instances")
	}
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}