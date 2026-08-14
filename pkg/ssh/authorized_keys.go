package ssh

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// DefaultLockDir is where the broker keeps the per-user lock files that serialize
// its own authorized_keys writes.
//
// (#161) The locks used to live in the user's own ~/.ssh, where the user could
// take them: `flock ~/.ssh/authorized_keys.lock -c 'sleep infinity'` blocked the
// broker's next write to that file forever, because the lock was acquired with a
// blocking LOCK_EX. One unprivileged local user could therefore wedge the broker's
// single session-expiry goroutine — after which no session expired, no key was
// revoked for *any* user on the host, and `systemctl restart` hung on Stop() until
// SIGKILL.
//
// A lock whose only job is to serialize the broker against itself has no business
// being reachable by the account it is protecting, so it lives in the broker's own
// state directory.
const DefaultLockDir = "/var/lib/oidc-pam/locks"

const (
	// lockAcquireTimeout bounds how long a write waits for the per-user lock.
	// Nothing outside the broker can hold it now, so reaching this means another
	// broker instance, or a bug; either way the caller gets an error and the
	// goroutine keeps running.
	lockAcquireTimeout = 5 * time.Second

	// lockRetryInterval is how often a blocked writer retries.
	lockRetryInterval = 50 * time.Millisecond
)

// ErrLockUnavailable is returned when the per-user lock could not be taken within
// lockAcquireTimeout. It is a distinct error so a caller can tell "someone else is
// writing" from "the write failed".
var ErrLockUnavailable = errors.New("authorized_keys lock unavailable")

// withFileLock acquires an exclusive file lock, runs fn, then releases it. This
// serializes concurrent read-then-write operations on one user's authorized_keys.
//
// The lock is taken non-blocking with a bounded retry, so no lock holder — however
// it came to hold it — can park the calling goroutine indefinitely. That property
// is deliberately independent of where the lock file lives: it is what makes a
// future lock path, or a misconfigured state directory, unable to reintroduce
// #161.
//
// It serializes writers within one host. Two brokers writing the same NFS home
// from different hosts are not serialized by this, and never reliably were —
// flock over NFS is advisory at best — which is why every write goes through
// writeAuthorizedKeysAtomic rather than relying on the lock for integrity.
func withFileLock(lockPath string, timeout time.Duration, fn func() error) error {
	if err := ensureLockDir(filepath.Dir(lockPath)); err != nil {
		return err
	}

	// #nosec G304 -- lockPath is <lockDir>/<validated username>.lock in a directory
	// ensureLockDir has just checked is a real, broker-owned, non-group-writable
	// directory; O_NOFOLLOW prevents following a symlink at the lock path itself.
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
	}()

	if err := acquireLock(lockFile, lockPath, timeout); err != nil {
		return err
	}

	return fn()
}

// acquireLock takes an exclusive flock, retrying until timeout elapses.
func acquireLock(lockFile *os.File, lockPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("failed to acquire file lock %q: %w", lockPath, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: %q was held by another writer for longer than %s",
				ErrLockUnavailable, lockPath, timeout)
		}
		time.Sleep(lockRetryInterval)
	}
}

// ensureLockDir creates the lock directory if it is absent and refuses to use one
// that is not a directory the broker alone controls. A lock in a directory someone
// else can write to is not a lock: they can plant the lock file, or hold it.
func ensureLockDir(lockDir string) error {
	info, err := os.Lstat(lockDir)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(lockDir, 0700); mkErr != nil {
				return fmt.Errorf("failed to create lock directory %q: %w", lockDir, mkErr)
			}
			return nil
		}
		return fmt.Errorf("failed to stat lock directory %q: %w", lockDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use lock directory %q: it is a symlink", lockDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to use lock directory %q: it is not a directory", lockDir)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("refusing to use lock directory %q: mode %#o is writable by group or other",
			lockDir, info.Mode().Perm())
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("refusing to use lock directory %q: it is owned by uid %d, not by this process (uid %d)",
			lockDir, stat.Uid, os.Geteuid())
	}
	return nil
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
	// #nosec G304 -- path is built from an allowlisted username (validateUsername)
	// under the broker's base dir; the final component is symlink-checked above
	// and opened with O_NOFOLLOW so a planted symlink cannot redirect the write.
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
	// #nosec G304 -- tmpPath is under the validated .ssh dir and opened with
	// O_EXCL|O_NOFOLLOW, so it cannot follow or clobber a pre-existing symlink.
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
	baseDir     string
	lockDir     string
	lockTimeout time.Duration
}

// NewAuthorizedKeysManager creates a new authorized keys manager.
//
// baseDir is the parent of the users' home directories (production: /home).
// lockDir is where the per-user write locks live and must be a directory only the
// broker can write to — production passes DefaultLockDir. It is a required
// argument rather than a default with an override because a lock directory the
// protected user can reach is the whole of #161, and that is not something to
// arrive at by forgetting to pass an option.
func NewAuthorizedKeysManager(baseDir, lockDir string) *AuthorizedKeysManager {
	return &AuthorizedKeysManager{
		baseDir:     baseDir,
		lockDir:     lockDir,
		lockTimeout: lockAcquireTimeout,
	}
}

// LockPath returns the lock file serializing writes to one user's
// authorized_keys. The username is validated by every caller before use, so it
// cannot contain a separator or traverse out of lockDir.
func (akm *AuthorizedKeysManager) LockPath(username string) string {
	return filepath.Join(akm.lockDir, username+".lock")
}

// SetLockTimeout overrides how long a write waits for the per-user lock before
// giving up with ErrLockUnavailable.
//
// This exists so tests can exercise the contended path in milliseconds instead of
// seconds. Call it before the manager is used; it is not safe to change
// concurrently with a write.
func (akm *AuthorizedKeysManager) SetLockTimeout(d time.Duration) {
	akm.lockTimeout = d
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
	lockPath := akm.LockPath(username)

	// Create/verify .ssh directory, rejecting a symlinked .ssh (C-2).
	if err := ensureSecureSSHDir(sshDir); err != nil {
		return err
	}

	return withFileLock(lockPath, akm.lockTimeout, func() error {
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
	lockPath := akm.LockPath(username)

	// Check if .ssh directory exists; if not, nothing to remove
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return nil
	}

	return withFileLock(lockPath, akm.lockTimeout, func() error {
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

// RemoveExpiredKeys removes broker-issued keys older than 24 hours from a user's
// authorized_keys.
//
// Called from the broker's session-expiry pass. Its job is the keys no session
// accounts for: sessions live only in the broker's memory, so a restart orphans
// every key issued before it, leaving a working credential with nothing left to
// revoke it.
//
// The 24-hour cutoff is fixed and is not the configured session lifetime. It is
// read from the `@oidc-pam-<timestamp>` comment the broker writes, so a key whose
// comment is missing or malformed is retained rather than removed — cleanup fails
// safe, never early. Authoritative expiry is the broker session; this is
// best-effort maintenance.
func (akm *AuthorizedKeysManager) RemoveExpiredKeys(username string) error {
	if err := validateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}
	userHomeDir := filepath.Join(akm.baseDir, username)
	sshDir := filepath.Join(userHomeDir, ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	lockPath := akm.LockPath(username)

	// Check if .ssh directory exists; if not, nothing to clean
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return nil
	}

	return withFileLock(lockPath, akm.lockTimeout, func() error {
		// Read existing authorized_keys file (O_NOFOLLOW: never follow a symlink — C-2).
		if err := rejectIfSymlink(authorizedKeysPath); err != nil {
			return err
		}
		// #nosec G304 -- validated username path; symlink-checked above and opened O_NOFOLLOW.
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

			// L-14: expiry is read from the (broker-written) key comment. A
			// malformed/forged comment simply causes the key to be retained
			// (fail-safe for cleanup: it is never removed early), and the keys are
			// broker-generated so the comment is not attacker-controlled in the
			// supported flow. Authoritative expiry lives in the broker session;
			// this cleanup is best-effort. See TODO(L-3) in keys.go for moving
			// expiry to a separate metadata file.
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

// ListOIDCKeys lists all OIDC PAM keys in a user's authorized_keys file.
//
// Operator-facing: nothing in the authentication path calls this. It exists so
// that an administrator investigating a user's access can see which
// authorized_keys entries this broker is responsible for, distinguished from the
// user's own keys by the `@oidc-pam-<timestamp>` comment.
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

// BackupAuthorizedKeys creates a backup of the authorized_keys file.
//
// Operator-facing recovery API, paired with RestoreAuthorizedKeys; the broker
// does not call it during authentication. The key-management functions rewrite a
// file the user also owns, so a copy taken before a manual intervention is worth
// having.
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
	// #nosec G304 -- validated username path; symlink-checked above and opened O_NOFOLLOW.
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

// RestoreAuthorizedKeys restores the authorized_keys file from the backup taken
// by BackupAuthorizedKeys.
//
// Operator-facing recovery API; the broker does not call it. Note that it
// restores whatever was in the file at backup time, which will reinstate any
// broker-issued keys that were present then — run the expiry sweep afterwards if
// that matters.
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
