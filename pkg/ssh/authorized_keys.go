package ssh

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
// It rejects the operation if .ssh exists but is a symlink, is not a directory,
// or belongs to some third account. Callers must additionally open files within it
// using O_NOFOLLOW (see writeAuthorizedKeysAtomic).
//
// (#171) A .ssh directory the broker creates is handed to the account rather than
// kept by root. It sits in the user's home and the user has to be able to manage
// their own keys in it; a root-owned 0700 .ssh takes that away with no way for
// them to get it back.
func ensureSecureSSHDir(sshDir string, account Account) error {
	info, err := os.Lstat(sshDir)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(sshDir, 0700); mkErr != nil {
				return fmt.Errorf("failed to create .ssh directory: %w", mkErr)
			}
			return chownToAccount(sshDir, account)
		}
		return fmt.Errorf("failed to stat .ssh directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use .ssh: %q is a symlink", sshDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to use .ssh: %q is not a directory", sshDir)
	}
	return checkOwner(".ssh directory", sshDir, info, account)
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

// readAuthorizedKeysLines reads a user's authorized_keys and returns its lines.
// A missing file yields no lines and no error: a user who has never had a key is
// the normal case, not a failure.
//
// (#171) The file is opened O_NOFOLLOW and then *fstat'ed through the open
// descriptor*, and the descriptor is refused unless it belongs to the account or
// to root. Checking the path instead of the descriptor is a TOCTOU: the directory
// is writable by the user, so between a stat and an open the name can be made to
// point somewhere else. What is verified has to be the thing that was opened.
func readAuthorizedKeysLines(path string, account Account) ([]string, error) {
	if err := rejectIfSymlink(path); err != nil {
		return nil, err
	}
	// #nosec G304 -- path is <resolved home>/.ssh/authorized_keys for a validated
	// login name; symlink-checked above, opened O_NOFOLLOW, and the descriptor's
	// ownership is verified below.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open authorized_keys file: %w", err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat the open authorized_keys file: %w", err)
	}
	if err := checkOwner("authorized_keys", path, info, account); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read authorized_keys file: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n"), nil
}

// writeAuthorizedKeysAtomic writes content to the authorized_keys file safely:
// it refuses if the target is a symlink, writes to a temporary file in the same
// directory (created with O_NOFOLLOW|O_EXCL), then atomically renames over the
// target. Rename replaces the directory entry rather than following/truncating
// a link, so a planted symlink cannot redirect the write.
// The replacement is given to the account before the rename (#171): the broker
// runs as root, and a file it created would otherwise leave the user unable to
// edit their own authorized_keys.
func writeAuthorizedKeysAtomic(sshDir, path string, content []byte, account Account) error {
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
	if err := chownToAccount(tmpPath, account); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("failed to replace authorized_keys: %w", err)
	}
	return nil
}

// writeAuthorizedKeysLines renders the surviving lines back to authorized_keys,
// guaranteeing the file ends in exactly one newline.
//
// (#165) Both rewrite paths go through this because they used to disagree, and one
// of them was wrong: RemovePublicKey split on "\n" — which keeps a trailing empty
// element, so Join restored the final newline — while RemoveExpiredKeys used a
// bufio.Scanner, which drops it. A file left without a final newline is not merely
// untidy: AddPublicKey appends with O_APPEND, so the next login fused its
// "# Added by OIDC PAM" comment onto the last surviving key line. The resulting
// entry still authorizes its holder but can never be removed again — the expiry
// sweep can no longer parse its timestamp and targeted revocation no longer matches
// the line — while the broker audited the failed removal as a success.
//
// Sharing one write path is the point: two callers deriving the file's tail
// independently is what allowed them to differ in the first place.
func writeAuthorizedKeysLines(sshDir, path string, lines []string, account Account) error {
	// Trailing blanks are dropped so that a caller's choice of line splitting
	// cannot change the file's tail, then the last real line is terminated.
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	var content []byte
	if len(lines) > 0 {
		content = []byte(strings.Join(lines, "\n") + "\n")
	}
	return writeAuthorizedKeysAtomic(sshDir, path, content, account)
}

// DefaultKeyLifetime is the age at which a broker-issued authorized_keys entry is
// treated as stale when nothing better is known about it. It is only a fallback:
// the broker sets the configured token_lifetime with SetKeyLifetime, and entries
// written by this version carry their own expiry-time= option.
const DefaultKeyLifetime = 24 * time.Hour

// AuthorizedKeysManager manages authorized_keys files for users
type AuthorizedKeysManager struct {
	lookupAccount AccountLookup
	lockDir       string
	lockTimeout   time.Duration
	keyLifetime   time.Duration
}

// NewAuthorizedKeysManager creates a new authorized keys manager.
//
// lockDir is where the per-user write locks live and must be a directory only the
// broker can write to — production passes DefaultLockDir. It is a required
// argument rather than a default with an override because a lock directory the
// protected user can reach is the whole of #161, and that is not something to
// arrive at by forgetting to pass an option.
//
// (#171) There is no base-directory argument any more. This used to be
// constructed with "/home" and every path was <baseDir>/<username>/.ssh, which is
// a guess: it is wrong on every site whose homes come from LDAP/SSSD, autofs or
// NFS, and being wrong meant writing a key list sshd never reads while reporting
// success. Homes now come from the account database (LookupAccount).
func NewAuthorizedKeysManager(lockDir string) *AuthorizedKeysManager {
	return &AuthorizedKeysManager{
		lookupAccount: LookupAccount,
		lockDir:       lockDir,
		lockTimeout:   lockAcquireTimeout,
		keyLifetime:   DefaultKeyLifetime,
	}
}

// SetAccountLookup replaces the account database this manager resolves homes and
// owners through.
//
// It exists for tests, which cannot create real accounts on the machine running
// the suite; see HomeRootLookup. Call it before the manager is used.
func (akm *AuthorizedKeysManager) SetAccountLookup(lookup AccountLookup) {
	if lookup != nil {
		akm.lookupAccount = lookup
	}
}

// SetKeyLifetime sets how long a broker-issued entry is honoured when the entry
// itself does not say — that is, an entry written by an older broker, which
// carries only the issue time in its comment.
//
// The broker passes the configured authentication.token_lifetime. Before #171 the
// sweep used a hardcoded 24 hours regardless of configuration, so a site that had
// deliberately configured a one-hour lifetime still left every key it issued
// usable for a day.
func (akm *AuthorizedKeysManager) SetKeyLifetime(d time.Duration) {
	if d > 0 {
		akm.keyLifetime = d
	}
}

// userPaths resolves an account and returns it with the paths of its .ssh
// directory and authorized_keys file.
//
// It refuses to proceed unless the home directory the account database names
// already exists and belongs to that account or to root. In particular it will
// not create a home: MkdirAll on <home>/.ssh used to create the home itself, as
// root and mode 0700, which locks the user out of their own home directory for a
// login that then cannot work anyway. A missing home means the account is not
// provisioned on this host, and that is a fact to report, not to paper over.
func (akm *AuthorizedKeysManager) userPaths(username string) (Account, string, string, error) {
	if err := validateUsername(username); err != nil {
		return Account{}, "", "", fmt.Errorf("invalid username: %w", err)
	}
	account, err := akm.lookupAccount(username)
	if err != nil {
		return Account{}, "", "", err
	}

	info, err := os.Lstat(account.Home)
	if err != nil {
		if os.IsNotExist(err) {
			return Account{}, "", "", fmt.Errorf(
				"home directory %q for %s does not exist; refusing to create it",
				account.Home, username)
		}
		return Account{}, "", "", fmt.Errorf("failed to stat home directory %q: %w", account.Home, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Account{}, "", "", fmt.Errorf("refusing to use home directory %q: it is a symlink", account.Home)
	}
	if !info.IsDir() {
		return Account{}, "", "", fmt.Errorf("refusing to use home directory %q: it is not a directory", account.Home)
	}
	if err := checkOwner("home directory", account.Home, info, account); err != nil {
		return Account{}, "", "", err
	}

	sshDir := filepath.Join(account.Home, ".ssh")
	return account, sshDir, filepath.Join(sshDir, "authorized_keys"), nil
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

// AddPublicKey installs the broker's key in a user's authorized_keys, as the
// user's only broker-issued key, carrying the expiry sshd will enforce on it.
//
// expiresAt must be in the future: an entry with no expiry, or one already expired,
// is not something to write into a key list and hope something removes later.
//
// (#171) Two things changed here, and both were ways a stale key stayed usable:
//
//   - It appended. Every login left another `@oidc-pam-` entry behind, deduplicated
//     only against a byte-identical line — and the comment carries the issue
//     timestamp, so no two logins ever produced one. A user who logged in daily
//     accumulated one permanently valid key per login, each independently
//     sufficient to authenticate, and revoking the current session's key left all
//     the others in place. Now every broker-issued entry for that user is dropped
//     before the new one is written: one live key, so revoking it revokes access.
//   - The expiry existed only in the broker's memory and in a comment nothing but
//     this broker reads. sshd now enforces it itself, which is what makes a key
//     survive neither a broker restart nor a broker that never gets around to
//     sweeping.
func (akm *AuthorizedKeysManager) AddPublicKey(username string, publicKey []byte, expiresAt time.Time) error {
	// Reject embedded newlines/CR: a multi-line value would inject additional
	// authorized_keys entries or options (e.g. command=) (M-8).
	if err := validatePublicKeyLine(publicKey); err != nil {
		return err
	}
	if expiresAt.IsZero() {
		return fmt.Errorf("refusing to install an SSH key with no expiry time")
	}
	if !expiresAt.After(time.Now()) {
		return fmt.Errorf("refusing to install an SSH key that expired at %s", expiresAt.UTC().Format(time.RFC3339))
	}

	account, sshDir, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return err
	}

	// Create/verify .ssh directory, rejecting a symlinked .ssh (C-2).
	if err := ensureSecureSSHDir(sshDir, account); err != nil {
		return err
	}

	newEntry, ok := parseKeyEntry(string(publicKey))
	if !ok {
		return fmt.Errorf("public key is not a valid authorized_keys entry")
	}

	return withFileLock(akm.LockPath(username), akm.lockTimeout, func() error {
		existing, err := readAuthorizedKeysLines(authorizedKeysPath, account)
		if err != nil {
			return err
		}

		// Keep everything that is not the broker's. A key the user put there
		// themselves is none of the broker's business, whatever it authorizes; only
		// entries carrying the broker's own marker, or a re-add of this very entry,
		// are dropped.
		kept := make([]string, 0, len(existing)+2)
		superseded := 0
		for _, line := range existing {
			entry, isEntry := parseKeyEntry(line)
			if isEntry && (entry.brokerIssued() || entry.isSameEntryAs(newEntry)) {
				superseded++
				continue
			}
			kept = append(kept, line)
		}
		kept = dropStrandedBrokerComments(kept)

		kept = append(kept,
			fmt.Sprintf("%s %s", brokerCommentPrefix, time.Now().Format("2006-01-02 15:04:05")),
			brokerEntryLine(publicKey, expiresAt))

		if err := writeAuthorizedKeysLines(sshDir, authorizedKeysPath, kept, account); err != nil {
			return fmt.Errorf("failed to write authorized_keys file: %w", err)
		}

		log.Info().
			Str("username", username).
			Str("authorized_keys_path", authorizedKeysPath).
			Int("superseded_keys", superseded).
			Time("expires_at", expiresAt).
			Msg("Public key added to authorized_keys")

		return nil
	})
}

// RemovePublicKey removes a public key from a user's authorized_keys file. It
// reports whether a matching line was actually found and removed.
//
// (#165) The removed flag is not decoration. This used to return only an error, and
// nil for both "the line is gone" and "there was no such line", so the broker logged
// "SSH key revoked" and recorded a revoke-success metric for a removal that changed
// nothing — the audit trail asserted a revocation that had not happened while the
// credential stayed usable. Callers must distinguish the two: removed=false, err=nil
// means the entry is still there, if it was ever there at all.
// (#171) Matching is on the entry, not on the whole line: the installed line
// carries an `expiry-time=` option in front of the key, so a broker holding the
// bare key in its store would never again find the line it had itself written.
// parseKeyEntry/isSameEntryAs compare the key and its comment and ignore options.
func (akm *AuthorizedKeysManager) RemovePublicKey(username string, publicKey []byte) (bool, error) {
	account, sshDir, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return false, err
	}

	// Check if .ssh directory exists; if not, nothing to remove
	if _, statErr := os.Stat(sshDir); os.IsNotExist(statErr) {
		return false, nil
	}

	target, ok := parseKeyEntry(string(publicKey))
	if !ok {
		return false, fmt.Errorf("public key is not a valid authorized_keys entry")
	}

	removed := false
	err = withFileLock(akm.LockPath(username), akm.lockTimeout, func() error {
		lines, err := readAuthorizedKeysLines(authorizedKeysPath, account)
		if err != nil {
			return err
		}

		filteredLines := make([]string, 0, len(lines))
		for _, line := range lines {
			if entry, isEntry := parseKeyEntry(line); isEntry && entry.isSameEntryAs(target) {
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
		if err := writeAuthorizedKeysLines(sshDir, authorizedKeysPath,
			dropStrandedBrokerComments(filteredLines), account); err != nil {
			return fmt.Errorf("failed to write authorized_keys file: %w", err)
		}

		log.Info().
			Str("username", username).
			Str("authorized_keys_path", authorizedKeysPath).
			Msg("Public key removed from authorized_keys")

		return nil
	})
	if err != nil {
		return false, err
	}
	return removed, nil
}

// KeyIsAuthorized reports whether this key material still authorizes access to the
// account, whatever entry or options carry it.
//
// (#171) The broker needs this to tell the two reasons a removal matched nothing
// apart. "The entry is gone because a later login superseded it" is the system
// working; "the entry is still there under some line this code could not match" is
// a credential that outlived its session, and only the second is worth an alarm.
// Without the distinction, one-live-key-per-user would make every revocation of a
// superseded key look like a failed revocation.
func (akm *AuthorizedKeysManager) KeyIsAuthorized(username string, publicKey []byte) (bool, error) {
	account, _, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return false, err
	}
	target, ok := parseKeyEntry(string(publicKey))
	if !ok {
		return false, fmt.Errorf("public key is not a valid authorized_keys entry")
	}

	lines, err := readAuthorizedKeysLines(authorizedKeysPath, account)
	if err != nil {
		return false, err
	}
	for _, line := range lines {
		if entry, isEntry := parseKeyEntry(line); isEntry && entry.authorizesSameKeyAs(target) {
			return true, nil
		}
	}
	return false, nil
}

// RemoveOIDCKeys removes every broker-issued entry from a user's authorized_keys
// and reports how many it removed.
//
// This is what makes a broker restart safe. Sessions live in memory, so a broker
// that restarts has no record of the keys it issued and nothing left that would
// ever revoke them; the sweep only helped users who happened to have another
// session expire afterwards. The broker now calls this at startup for every key it
// finds in its own store (#171).
func (akm *AuthorizedKeysManager) RemoveOIDCKeys(username string) (int, error) {
	account, sshDir, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return 0, err
	}

	removed := 0
	err = withFileLock(akm.LockPath(username), akm.lockTimeout, func() error {
		lines, err := readAuthorizedKeysLines(authorizedKeysPath, account)
		if err != nil {
			return err
		}
		kept := make([]string, 0, len(lines))
		for _, line := range lines {
			if entry, isEntry := parseKeyEntry(line); isEntry && entry.brokerIssued() {
				removed++
				continue
			}
			kept = append(kept, line)
		}
		if removed == 0 {
			return nil
		}
		return writeAuthorizedKeysLines(sshDir, authorizedKeysPath, dropStrandedBrokerComments(kept), account)
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

// RemoveExpiredKeys removes broker-issued keys whose expiry has passed from a
// user's authorized_keys.
//
// Called from the broker's session-expiry pass. Its job is the keys no session
// accounts for: sessions live only in the broker's memory, so a restart orphans
// every key issued before it. (Since #171 the broker also reconciles its key store
// at startup, and every entry it writes carries an expiry sshd enforces by itself,
// so this is no longer the only thing standing between a restart and a permanent
// credential.)
//
// The expiry is taken from the entry's own `expiry-time=` option, and for entries
// written by an older broker from the `@oidc-pam-<timestamp>` comment plus the
// configured key lifetime (SetKeyLifetime). A key whose expiry cannot be
// determined either way is retained rather than removed — cleanup fails safe,
// never early.
//
// (#171) The cutoff used to be a hardcoded 24 hours whatever the site had
// configured, and the timestamp was read out of `strings.Fields(line)[2]`, which is
// the key data rather than the comment for any entry that carries options — so the
// sweep would have silently stopped recognising the broker's own keys.
func (akm *AuthorizedKeysManager) RemoveExpiredKeys(username string) error {
	account, sshDir, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return err
	}

	// Check if .ssh directory exists; if not, nothing to clean
	if _, statErr := os.Stat(sshDir); os.IsNotExist(statErr) {
		return nil
	}

	return withFileLock(akm.LockPath(username), akm.lockTimeout, func() error {
		lines, err := readAuthorizedKeysLines(authorizedKeysPath, account)
		if err != nil {
			return err
		}

		now := time.Now()
		filteredLines := make([]string, 0, len(lines))
		removedCount := 0
		for _, line := range lines {
			if akm.entryHasExpired(line, now) {
				removedCount++
				continue
			}
			filteredLines = append(filteredLines, line)
		}

		if removedCount == 0 {
			return nil
		}

		// Write filtered content back atomically, refusing to follow symlinks (C-2).
		// Line splitting has stripped every line's newline, so the shared writer is
		// what puts the file's final one back (#165).
		if err := writeAuthorizedKeysLines(sshDir, authorizedKeysPath,
			dropStrandedBrokerComments(filteredLines), account); err != nil {
			return fmt.Errorf("failed to write authorized_keys file: %w", err)
		}

		log.Info().
			Str("username", username).
			Int("removed_count", removedCount).
			Msg("Removed expired OIDC PAM keys from authorized_keys")

		return nil
	})
}

// entryHasExpired reports whether a line is a broker-issued entry that is past its
// expiry. Anything else — a blank line, a comment, a key the user owns, or a broker
// entry whose expiry cannot be read — is not expired as far as this is concerned.
func (akm *AuthorizedKeysManager) entryHasExpired(line string, now time.Time) bool {
	entry, ok := parseKeyEntry(line)
	if !ok || !entry.brokerIssued() {
		return false
	}
	// The option is what sshd itself honours, so it wins where both are present.
	if expiry, ok := entry.expiryTime(); ok {
		return now.After(expiry)
	}
	// An entry from a broker that predates expiry-time=: the comment records when it
	// was issued, and the configured lifetime says how long that was good for.
	if issued, ok := entry.issuedAt(); ok {
		return now.After(issued.Add(akm.keyLifetime))
	}
	return false
}

// ListOIDCKeys lists all OIDC PAM keys in a user's authorized_keys file.
//
// Operator-facing: nothing in the authentication path calls this. It exists so
// that an administrator investigating a user's access can see which
// authorized_keys entries this broker is responsible for, distinguished from the
// user's own keys by the `@oidc-pam-<timestamp>` comment.
func (akm *AuthorizedKeysManager) ListOIDCKeys(username string) ([]string, error) {
	account, _, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return nil, err
	}

	lines, err := readAuthorizedKeysLines(authorizedKeysPath, account)
	if err != nil {
		return nil, err
	}

	oidcKeys := []string{}
	for _, line := range lines {
		// Parsed rather than substring-matched so that an entry carrying options is
		// still recognised, and so that "@oidc-pam-" appearing anywhere other than
		// the comment does not make a line the broker's (#171).
		if entry, ok := parseKeyEntry(line); ok && entry.brokerIssued() {
			oidcKeys = append(oidcKeys, strings.TrimSpace(line))
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
	account, sshDir, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return err
	}
	backupPath := filepath.Join(sshDir, "authorized_keys.backup")

	// Check if original file exists
	if _, statErr := os.Stat(authorizedKeysPath); os.IsNotExist(statErr) {
		return nil // No file to backup
	}

	lines, err := readAuthorizedKeysLines(authorizedKeysPath, account)
	if err != nil {
		return err
	}
	var data []byte
	if len(lines) > 0 {
		data = []byte(strings.Join(lines, "\n") + "\n")
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
	// The backup sits in the user's own .ssh, so it is theirs, not root's (#171).
	if err := chownToAccount(backupPath, account); err != nil {
		return err
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
	account, sshDir, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return err
	}
	backupPath := filepath.Join(sshDir, "authorized_keys.backup")

	// Check if backup exists
	if _, statErr := os.Stat(backupPath); os.IsNotExist(statErr) {
		return fmt.Errorf("no backup file found")
	}

	// Copy backup to authorized_keys
	if err := rejectIfSymlink(backupPath); err != nil {
		return err
	}
	data, err := os.ReadFile(backupPath) // #nosec G304 -- resolved home, symlink-checked above
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	if err := ensureSecureSSHDir(sshDir, account); err != nil {
		return err
	}
	if err := writeAuthorizedKeysAtomic(sshDir, authorizedKeysPath, data, account); err != nil {
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
