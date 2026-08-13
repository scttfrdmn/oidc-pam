package ssh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// KeyManager handles SSH key lifecycle management
type KeyManager struct {
	baseDir    string
	keySize    int
	keyType    string
	expiration time.Duration
}

// SSHKey represents an SSH key pair
// TODO(L-3): Key expiry is currently carried in the SSH public key comment field
// (e.g. "oidc-pam:expires=<unix-timestamp>"). This is fragile because comment
// fields are user-visible and may be stripped by some authorized_keys parsers.
// A future refactor should store expiry in a separate metadata file alongside
// the key, keyed by the same identifier.
type SSHKey struct {
	PrivateKey []byte
	PublicKey  []byte
	Comment    string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// usernamePattern is a strict allowlist for POSIX-style login names: a leading
// lowercase letter or underscore, followed by lowercase letters, digits,
// underscores, or hyphens, with an optional trailing '$'. Anchored and length
// bounded. This is a positive allowlist (M-7) rather than a denylist, so it also
// rejects "..", path separators, leading dots, and other traversal tricks.
var usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}\$?$`)

// validateUsername rejects usernames that are not valid POSIX login names,
// which also prevents path-traversal when usernames are joined into filesystem
// paths under the broker's base directory.
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if !usernamePattern.MatchString(username) {
		return fmt.Errorf("username %q is not a valid POSIX login name", username)
	}
	return nil
}

// NewKeyManager creates a new SSH key manager
func NewKeyManager(baseDir string) *KeyManager {
	return &KeyManager{
		baseDir:    baseDir,
		keySize:    4096,
		keyType:    "rsa",
		expiration: 24 * time.Hour, // Default 24 hour expiration
	}
}

// SetKeySize sets the key size for generated keys
func (km *KeyManager) SetKeySize(size int) {
	km.keySize = size
}

// SetKeyType sets the key type for generated keys
func (km *KeyManager) SetKeyType(keyType string) {
	km.keyType = keyType
}

// SetExpiration sets the expiration time for generated keys
func (km *KeyManager) SetExpiration(duration time.Duration) {
	km.expiration = duration
}

// GenerateKey generates a new SSH key pair
func (km *KeyManager) GenerateKey(username string) (*SSHKey, error) {
	log.Info().
		Str("username", username).
		Int("key_size", km.keySize).
		Str("key_type", km.keyType).
		Msg("Generating SSH key pair")

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, km.keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Encode private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	// Generate public key
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %w", err)
	}

	// Create comment
	comment := fmt.Sprintf("%s@oidc-pam-%d", username, time.Now().Unix())

	// Format public key
	publicKeyBytes := ssh.MarshalAuthorizedKey(publicKey)

	// Add comment to public key
	publicKeyStr := strings.TrimSpace(string(publicKeyBytes)) + " " + comment
	publicKeyBytes = []byte(publicKeyStr + "\n")

	now := time.Now()
	sshKey := &SSHKey{
		PrivateKey: privateKeyBytes,
		PublicKey:  publicKeyBytes,
		Comment:    comment,
		CreatedAt:  now,
		ExpiresAt:  now.Add(km.expiration),
	}

	log.Info().
		Str("username", username).
		Time("expires_at", sshKey.ExpiresAt).
		Msg("SSH key pair generated successfully")

	return sshKey, nil
}

// SaveKey saves an SSH key pair to disk
func (km *KeyManager) SaveKey(username string, key *SSHKey) error {
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}
	userDir := filepath.Join(km.baseDir, username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return fmt.Errorf("failed to create user directory: %w", err)
	}

	// Save private key
	privateKeyPath := filepath.Join(userDir, "id_rsa")
	if err := os.WriteFile(privateKeyPath, key.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save public key
	publicKeyPath := filepath.Join(userDir, "id_rsa.pub")
	if err := os.WriteFile(publicKeyPath, key.PublicKey, 0644); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	// Save metadata
	metadataPath := filepath.Join(userDir, "key_metadata")
	metadata := fmt.Sprintf("created_at=%d\nexpires_at=%d\ncomment=%s\n",
		key.CreatedAt.Unix(),
		key.ExpiresAt.Unix(),
		key.Comment)
	if err := os.WriteFile(metadataPath, []byte(metadata), 0600); err != nil {
		return fmt.Errorf("failed to save key metadata: %w", err)
	}

	log.Info().
		Str("username", username).
		Str("private_key_path", privateKeyPath).
		Str("public_key_path", publicKeyPath).
		Msg("SSH key pair saved successfully")

	return nil
}

// LoadKey loads an SSH key pair from disk
func (km *KeyManager) LoadKey(username string) (*SSHKey, error) {
	if err := validateUsername(username); err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}
	userDir := filepath.Join(km.baseDir, username)

	// Load private key
	privateKeyPath := filepath.Join(userDir, "id_rsa")
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	// Load public key
	publicKeyPath := filepath.Join(userDir, "id_rsa.pub")
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key: %w", err)
	}

	// Load metadata
	metadataPath := filepath.Join(userDir, "key_metadata")
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key metadata: %w", err)
	}

	// Parse metadata
	metadata := parseMetadata(string(metadataBytes))

	createdAt, err := parseTimestamp(metadata["created_at"])
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	expiresAt, err := parseTimestamp(metadata["expires_at"])
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
	}

	sshKey := &SSHKey{
		PrivateKey: privateKeyBytes,
		PublicKey:  publicKeyBytes,
		Comment:    metadata["comment"],
		CreatedAt:  createdAt,
		ExpiresAt:  expiresAt,
	}

	return sshKey, nil
}

// DeleteKey removes an SSH key pair from disk
func (km *KeyManager) DeleteKey(username string) error {
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}
	userDir := filepath.Join(km.baseDir, username)

	// Remove all key files
	files := []string{"id_rsa", "id_rsa.pub", "key_metadata"}
	for _, file := range files {
		filePath := filepath.Join(userDir, file)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove %s: %w", file, err)
		}
	}

	// Remove directory if empty
	if err := os.Remove(userDir); err != nil && !os.IsNotExist(err) {
		log.Debug().
			Str("username", username).
			Str("user_dir", userDir).
			Err(err).
			Msg("Failed to remove user directory (may not be empty)")
	}

	log.Info().
		Str("username", username).
		Msg("SSH key pair deleted successfully")

	return nil
}

// IsKeyExpired checks if an SSH key is expired
func (km *KeyManager) IsKeyExpired(key *SSHKey) bool {
	return time.Now().After(key.ExpiresAt)
}

// GetKeyPath returns the path to the SSH key for a user
func (km *KeyManager) GetKeyPath(username string) string {
	if validateUsername(username) != nil {
		return ""
	}
	return filepath.Join(km.baseDir, username, "id_rsa")
}

// GetPublicKeyPath returns the path to the SSH public key for a user
func (km *KeyManager) GetPublicKeyPath(username string) string {
	if validateUsername(username) != nil {
		return ""
	}
	return filepath.Join(km.baseDir, username, "id_rsa.pub")
}

// ListKeys lists all SSH keys managed by this key manager
func (km *KeyManager) ListKeys() ([]string, error) {
	entries, err := os.ReadDir(km.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read base directory: %w", err)
	}

	var users []string
	for _, entry := range entries {
		if entry.IsDir() {
			// Check if this directory contains SSH keys
			privateKeyPath := filepath.Join(km.baseDir, entry.Name(), "id_rsa")
			if _, err := os.Stat(privateKeyPath); err == nil {
				users = append(users, entry.Name())
			}
		}
	}

	return users, nil
}

// CleanupExpiredKeys removes expired SSH keys
func (km *KeyManager) CleanupExpiredKeys() error {
	users, err := km.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	var cleaned []string
	for _, username := range users {
		key, err := km.LoadKey(username)
		if err != nil {
			log.Error().
				Str("username", username).
				Err(err).
				Msg("Failed to load key for cleanup check")
			continue
		}

		if km.IsKeyExpired(key) {
			if err := km.DeleteKey(username); err != nil {
				log.Error().
					Str("username", username).
					Err(err).
					Msg("Failed to delete expired key")
			} else {
				cleaned = append(cleaned, username)
			}
		}
	}

	if len(cleaned) > 0 {
		log.Info().
			Strs("users", cleaned).
			Msg("Cleaned up expired SSH keys")
	}

	return nil
}

// KeyInfo is the public metadata of one managed key pair, for operator-facing
// listings. It deliberately carries no key material: `oidc-admin keys` wants to
// know which users have keys, how strong they are and when they expire.
type KeyInfo struct {
	Username string
	// KeyType is the SSH algorithm name from the public key itself
	// (e.g. "ssh-rsa"), not the manager's configured key type — an existing key
	// may predate a configuration change.
	KeyType string
	// KeySize is the key's strength in bits, or 0 if it cannot be determined
	// from the public key.
	KeySize   int
	CreatedAt time.Time
	ExpiresAt time.Time
	Expired   bool
}

// ListKeyInfo returns metadata for every managed key pair.
//
// A key whose files cannot be read or parsed is skipped and counted in the
// second return value rather than failing the whole listing: one half-written
// directory should not make the listing unavailable, but a silently short list
// would read as "these are all the keys".
func (km *KeyManager) ListKeyInfo() ([]KeyInfo, int, error) {
	users, err := km.ListKeys()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list keys: %w", err)
	}

	infos := make([]KeyInfo, 0, len(users))
	unreadable := 0
	for _, username := range users {
		key, err := km.LoadKey(username)
		if err != nil {
			log.Warn().
				Str("username", username).
				Err(err).
				Msg("Skipping key that could not be read while listing keys")
			unreadable++
			continue
		}

		keyType, keySize := publicKeyStrength(key.PublicKey)
		infos = append(infos, KeyInfo{
			Username:  username,
			KeyType:   keyType,
			KeySize:   keySize,
			CreatedAt: key.CreatedAt,
			ExpiresAt: key.ExpiresAt,
			Expired:   km.IsKeyExpired(key),
		})
	}

	return infos, unreadable, nil
}

// publicKeyStrength reports an authorized_keys line's algorithm name and size in
// bits. An unparseable line yields ("unknown", 0); a parseable one whose size we
// cannot derive keeps its algorithm name and a size of 0, since the algorithm is
// still worth showing.
func publicKeyStrength(publicKey []byte) (string, int) {
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return "unknown", 0
	}

	keyType := parsed.Type()

	cryptoKey, ok := parsed.(ssh.CryptoPublicKey)
	if !ok {
		return keyType, 0
	}

	switch pub := cryptoKey.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		return keyType, pub.N.BitLen()
	case *ecdsa.PublicKey:
		return keyType, pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		// Ed25519 keys have one size; there is no parameter to read.
		return keyType, ed25519.PublicKeySize * 8
	default:
		return keyType, 0
	}
}

// parseMetadata parses key metadata from a string
func parseMetadata(data string) map[string]string {
	metadata := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(data), "\n")

	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			metadata[parts[0]] = parts[1]
		}
	}

	return metadata
}

// parseTimestamp parses a Unix timestamp string
func parseTimestamp(ts string) (time.Time, error) {
	if ts == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}

	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp: %w", err)
	}

	return time.Unix(timestamp, 0), nil
}
