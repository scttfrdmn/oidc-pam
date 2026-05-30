package ssh

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// withFileLock acquires an exclusive POSIX file lock on a lockfile adjacent to
// the authorized_keys file, runs fn, then releases the lock. This serializes
// concurrent read-then-write operations across processes.
//
// The lock file is opened with O_NOFOLLOW so a symlink planted at the lock path
// (in a user-controlled .ssh directory) cannot redirect the open to another
// file (see ensureSecureSSHDir for the surrounding symlink defenses).
func withFileLock(lockPath string, fn func() error) error {
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
	}()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to acquire file lock: %w", err)
	}

	return fn()
}

// ensureSecureSSHDir verifies that the user's .ssh directory is safe for the
// root broker to write into, creating it if absent. It defends against symlink
// attacks (CVE-class TOCTOU): a user owns their own ~/.ssh and could point it,
// or authorized_keys within it, at an arbitrary file (e.g. /etc/passwd) so that
// the root process follows the link and writes/truncates the target.
//
// It rejects the operation if .ssh exists but is a symlink or not a directory.
// Callers must additionally open files within it using O_NOFOLLOW (see
// openAuthorizedKeysForAppend / writeAuthorizedKeysAtomic).
func ensureSecureSSHDir(sshDir string) error {
	info, err := os.Lstat(sshDir)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(sshDir, 0700); mkErr != nil {
				return fmt.Errorf("failed to create .ssh directory: %w", mkErr)
			}
			return nil
		}
		return fmt.Errorf("failed to stat .ssh directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use .ssh: %q is a symlink", sshDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to use .ssh: %q is not a directory", sshDir)
	}
	return nil
}

// rejectIfSymlink returns an error if path exists and is a symbolic link. Used
// before opening/replacing authorized_keys so the root broker never follows a
// user-planted link.
func rejectIfSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to operate on %q: it is a symlink", path)
	}
	return nil
}

// openAuthorizedKeysForAppend opens the authorized_keys file for appending with
// O_NOFOLLOW, refusing to follow a symlink at the final path component.
func openAuthorizedKeysForAppend(path string) (*os.File, error) {
	if err := rejectIfSymlink(path); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
}

// writeAuthorizedKeysAtomic writes content to the authorized_keys file safely:
// it refuses if the target is a symlink, writes to a temporary file in the same
// directory (created with O_NOFOLLOW|O_EXCL), then atomically renames over the
// target. Rename replaces the directory entry rather than following/truncating
// a link, so a planted symlink cannot redirect the write.
func writeAuthorizedKeysAtomic(sshDir, path string, content []byte) error {
	if err := rejectIfSymlink(path); err != nil {
		return err
	}
	tmpPath := filepath.Join(sshDir, fmt.Sprintf(".authorized_keys.tmp.%d", os.Getpid()))
	_ = os.Remove(tmpPath) // clear any stale temp from a prior crash
	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp authorized_keys: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("failed to write temp authorized_keys: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("failed to close temp authorized_keys: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("failed to replace authorized_keys: %w", err)
	}
	return nil
}

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
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}
	// Reject embedded newlines/CR: a multi-line value would inject additional
	// authorized_keys entries or options (e.g. command=) (M-8).
	if err := validatePublicKeyLine(publicKey); err != nil {
		return err
	}
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	lockPath := filepath.Join(sshDir, "authorized_keys.lock")

	// Create/verify .ssh directory, rejecting a symlinked .ssh (C-2).
	if err := ensureSecureSSHDir(sshDir); err != nil {
		return err
	}

	return withFileLock(lockPath, func() error {
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

		// Add the new key (O_NOFOLLOW: never follow a planted symlink — C-2).
		file, err := openAuthorizedKeysForAppend(authorizedKeysPath)
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
	})
}

// RemovePublicKey removes a public key from a user's authorized_keys file
func (akm *AuthorizedKeysManager) RemovePublicKey(username string, publicKey []byte) error {
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	lockPath := filepath.Join(sshDir, "authorized_keys.lock")

	// Check if .ssh directory exists; if not, nothing to remove
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return nil
	}

	return withFileLock(lockPath, func() error {
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

		// Write filtered content back atomically, refusing to follow symlinks (C-2).
		newContent := strings.Join(filteredLines, "\n")
		if err := writeAuthorizedKeysAtomic(sshDir, authorizedKeysPath, []byte(newContent)); err != nil {
			return fmt.Errorf("failed to write authorized_keys file: %w", err)
		}

		log.Info().
			Str("username", username).
			Str("authorized_keys_path", authorizedKeysPath).
			Msg("Public key removed from authorized_keys")

		return nil
	})
}

// RemoveExpiredKeys removes expired OIDC PAM keys from authorized_keys
func (akm *AuthorizedKeysManager) RemoveExpiredKeys(username string) error {
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	lockPath := filepath.Join(sshDir, "authorized_keys.lock")

	// Check if .ssh directory exists; if not, nothing to clean
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return nil
	}

	return withFileLock(lockPath, func() error {
		// Read existing authorized_keys file (O_NOFOLLOW: never follow a symlink — C-2).
		if err := rejectIfSymlink(authorizedKeysPath); err != nil {
			return err
		}
		file, err := os.OpenFile(authorizedKeysPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
			// Write filtered content back atomically, refusing to follow symlinks (C-2).
			newContent := strings.Join(filteredLines, "\n")
			if err := writeAuthorizedKeysAtomic(sshDir, authorizedKeysPath, []byte(newContent)); err != nil {
				return fmt.Errorf("failed to write authorized_keys file: %w", err)
			}

			log.Info().
				Str("username", username).
				Int("removed_count", removedCount).
				Msg("Removed expired OIDC PAM keys from authorized_keys")
		}

		return nil
	})
}

// ListOIDCKeys lists all OIDC PAM keys in a user's authorized_keys file
func (akm *AuthorizedKeysManager) ListOIDCKeys(username string) ([]string, error) {
	if err := validateUsername(username); err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}
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
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	backupPath := filepath.Join(sshDir, "authorized_keys.backup")

	// Check if original file exists
	if _, err := os.Stat(authorizedKeysPath); os.IsNotExist(err) {
		return nil // No file to backup
	}

	// Copy the file (refuse to read through a symlinked authorized_keys — C-2).
	if err := rejectIfSymlink(authorizedKeysPath); err != nil {
		return err
	}
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		return fmt.Errorf("failed to read authorized_keys file: %w", err)
	}

	// Write the backup without following a planted symlink at the backup path.
	if err := rejectIfSymlink(backupPath); err != nil {
		return err
	}
	bf, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	if _, err := bf.Write(data); err != nil {
		_ = bf.Close()
		return fmt.Errorf("failed to create backup: %w", err)
	}
	if err := bf.Close(); err != nil {
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
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	backupPath := filepath.Join(sshDir, "authorized_keys.backup")

	// Check if backup exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("no backup file found")
	}

	// Copy backup to authorized_keys
	if err := rejectIfSymlink(backupPath); err != nil {
		return err
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	if err := ensureSecureSSHDir(sshDir); err != nil {
		return err
	}
	if err := writeAuthorizedKeysAtomic(sshDir, authorizedKeysPath, data); err != nil {
		return fmt.Errorf("failed to restore authorized_keys: %w", err)
	}

	log.Info().
		Str("username", username).
		Str("backup_path", backupPath).
		Msg("Restored authorized_keys from backup")

	return nil
}

// validatePublicKeyLine rejects a public key value that is empty or contains
// embedded newline/carriage-return characters. Without this, a multi-line value
// written to authorized_keys would inject additional key entries or per-key
// options such as command=/no-pty (M-8).
func validatePublicKeyLine(publicKey []byte) error {
	keyStr := strings.TrimSpace(string(publicKey))
	if keyStr == "" {
		return fmt.Errorf("empty public key")
	}
	if strings.ContainsAny(keyStr, "\n\r") {
		return fmt.Errorf("public key contains embedded newline characters")
	}
	return nil
}

// ValidateKeyFormat validates that a public key is in the correct format
func (akm *AuthorizedKeysManager) ValidateKeyFormat(publicKey []byte) error {
	if err := validatePublicKeyLine(publicKey); err != nil {
		return err
	}
	keyStr := strings.TrimSpace(string(publicKey))

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
