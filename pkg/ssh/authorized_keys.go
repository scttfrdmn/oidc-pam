package ssh

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// AuthorizedKeysManager manages authorized_keys files for users
type AuthorizedKeysManager struct {
	baseDir string
}

// NewAuthorizedKeysManager creates a new authorized keys manager
func NewAuthorizedKeysManager(baseDir string) *AuthorizedKeysManager {
	return &AuthorizedKeysManager{
		baseDir: baseDir,
	}
}

// AddPublicKey adds a public key to a user's authorized_keys file
func (akm *AuthorizedKeysManager) AddPublicKey(username string, publicKey []byte) error {
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")

	// Create .ssh directory if it doesn't exist
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Read existing authorized_keys file
	var existingKeys []string
	if data, err := os.ReadFile(authorizedKeysPath); err == nil {
		existingKeys = strings.Split(string(data), "\n")
	}

	// Check if key already exists
	newKeyLine := strings.TrimSpace(string(publicKey))
	for _, existingKey := range existingKeys {
		if strings.TrimSpace(existingKey) == newKeyLine {
			log.Debug().
				Str("username", username).
				Msg("Public key already exists in authorized_keys")
			return nil
		}
	}

	// Add the new key
	file, err := os.OpenFile(authorizedKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open authorized_keys file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Add timestamp comment
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	comment := fmt.Sprintf("# Added by OIDC PAM on %s\n", timestamp)
	
	if _, err := file.WriteString(comment); err != nil {
		return fmt.Errorf("failed to write comment to authorized_keys: %w", err)
	}

	if _, err := file.WriteString(newKeyLine + "\n"); err != nil {
		return fmt.Errorf("failed to write key to authorized_keys: %w", err)
	}

	log.Info().
		Str("username", username).
		Str("authorized_keys_path", authorizedKeysPath).
		Msg("Public key added to authorized_keys")

	return nil
}

// RemovePublicKey removes a public key from a user's authorized_keys file
func (akm *AuthorizedKeysManager) RemovePublicKey(username string, publicKey []byte) error {
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")

	// Read existing authorized_keys file
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, nothing to remove
		}
		return fmt.Errorf("failed to read authorized_keys file: %w", err)
	}

	// Parse existing keys
	lines := strings.Split(string(data), "\n")
	keyToRemove := strings.TrimSpace(string(publicKey))
	
	var filteredLines []string
	removed := false
	
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == keyToRemove {
			removed = true
			continue
		}
		filteredLines = append(filteredLines, line)
	}

	if !removed {
		log.Debug().
			Str("username", username).
			Msg("Public key not found in authorized_keys")
		return nil
	}

	// Write filtered content back
	newContent := strings.Join(filteredLines, "\n")
	if err := os.WriteFile(authorizedKeysPath, []byte(newContent), 0600); err != nil {
		return fmt.Errorf("failed to write authorized_keys file: %w", err)
	}

	log.Info().
		Str("username", username).
		Str("authorized_keys_path", authorizedKeysPath).
		Msg("Public key removed from authorized_keys")

	return nil
}

// RemoveExpiredKeys removes expired OIDC PAM keys from authorized_keys
func (akm *AuthorizedKeysManager) RemoveExpiredKeys(username string) error {
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")

	// Read existing authorized_keys file
	file, err := os.Open(authorizedKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, nothing to clean
		}
		return fmt.Errorf("failed to open authorized_keys file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var filteredLines []string
	var removedCount int
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := scanner.Text()
		
		// Check if this is an OIDC PAM key
		if strings.Contains(line, "@oidc-pam-") {
			// Extract timestamp from comment
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				comment := parts[2]
				if strings.Contains(comment, "@oidc-pam-") {
					// Extract timestamp
					timestampStr := strings.Split(comment, "@oidc-pam-")[1]
					if timestamp, err := strconv.ParseInt(timestampStr, 10, 64); err == nil {
						keyTime := time.Unix(timestamp, 0)
						// Check if key is older than 24 hours (default expiration)
						if time.Since(keyTime) > 24*time.Hour {
							removedCount++
							continue // Skip this line (remove the key)
						}
					}
				}
			}
		}
		
		filteredLines = append(filteredLines, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to scan authorized_keys file: %w", err)
	}

	if removedCount > 0 {
		// Write filtered content back
		newContent := strings.Join(filteredLines, "\n")
		if err := os.WriteFile(authorizedKeysPath, []byte(newContent), 0600); err != nil {
			return fmt.Errorf("failed to write authorized_keys file: %w", err)
		}

		log.Info().
			Str("username", username).
			Int("removed_count", removedCount).
			Msg("Removed expired OIDC PAM keys from authorized_keys")
	}

	return nil
}

// ListOIDCKeys lists all OIDC PAM keys in a user's authorized_keys file
func (akm *AuthorizedKeysManager) ListOIDCKeys(username string) ([]string, error) {
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")

	// Read existing authorized_keys file
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read authorized_keys file: %w", err)
	}

	var oidcKeys []string
	lines := strings.Split(string(data), "\n")
	
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") {
			if strings.Contains(trimmedLine, "@oidc-pam-") {
				oidcKeys = append(oidcKeys, trimmedLine)
			}
		}
	}

	return oidcKeys, nil
}

// BackupAuthorizedKeys creates a backup of the authorized_keys file
func (akm *AuthorizedKeysManager) BackupAuthorizedKeys(username string) error {
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	backupPath := filepath.Join(sshDir, "authorized_keys.backup")

	// Check if original file exists
	if _, err := os.Stat(authorizedKeysPath); os.IsNotExist(err) {
		return nil // No file to backup
	}

	// Copy the file
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		return fmt.Errorf("failed to read authorized_keys file: %w", err)
	}

	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	log.Info().
		Str("username", username).
		Str("backup_path", backupPath).
		Msg("Created authorized_keys backup")

	return nil
}

// RestoreAuthorizedKeys restores the authorized_keys file from backup
func (akm *AuthorizedKeysManager) RestoreAuthorizedKeys(username string) error {
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	backupPath := filepath.Join(sshDir, "authorized_keys.backup")

	// Check if backup exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("no backup file found")
	}

	// Copy backup to authorized_keys
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	if err := os.WriteFile(authorizedKeysPath, data, 0600); err != nil {
		return fmt.Errorf("failed to restore authorized_keys: %w", err)
	}

	log.Info().
		Str("username", username).
		Str("backup_path", backupPath).
		Msg("Restored authorized_keys from backup")

	return nil
}

// ValidateKeyFormat validates that a public key is in the correct format
func (akm *AuthorizedKeysManager) ValidateKeyFormat(publicKey []byte) error {
	keyStr := strings.TrimSpace(string(publicKey))
	
	if keyStr == "" {
		return fmt.Errorf("empty public key")
	}

	parts := strings.Fields(keyStr)
	if len(parts) < 2 {
		return fmt.Errorf("invalid public key format: missing key type or key data")
	}

	keyType := parts[0]
	validTypes := []string{"ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
	
	validType := false
	for _, validKeyType := range validTypes {
		if keyType == validKeyType {
			validType = true
			break
		}
	}

	if !validType {
		return fmt.Errorf("invalid key type: %s", keyType)
	}

	return nil
}