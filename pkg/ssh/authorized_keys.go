package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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

	// maxAuthorizedKeysBytes bounds how much of a user's authorized_keys the broker
	// will read into memory.
	//
	// (#206) There was no bound. io.ReadAll was pointed at a file in the user's own
	// directory, so `truncate -s 200G ~/.ssh/authorized_keys` — sparse, instant, no
	// quota cost — followed by a login grew a 200 GB slice and the root broker was
	// OOM-killed. Every other account's authentication fails while it is down, systemd
	// restarts it ten seconds later (Restart=always, no MemoryMax), startup reconcile
	// reads the same file for any user with a stored key, and it is killed again: a
	// host-wide authentication outage that persists until an operator finds the file.
	//
	// 1 MiB is the bound because of what the file legitimately holds. The largest
	// entry anyone writes is an options list plus a 16384-bit RSA key — about 2.8 KB
	// of base64 — plus a comment, so under 3 KB; a 4096-bit RSA entry is about 750
	// bytes and an ed25519 entry about 100. 1 MiB is therefore roughly 350 of the
	// largest entries that exist, 1,300 ordinary RSA ones, or 10,000 ed25519 ones, for
	// a single account. Nothing legitimate is near that, and a file that exceeds it is
	// refused rather than truncated: silently dropping the tail of a key list would
	// mean writing back a file with keys missing.
	maxAuthorizedKeysBytes = 1 << 20
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
	return ensureBrokerOwnedDir("lock directory", lockDir)
}

// ensureBrokerOwnedDir creates one of the broker's own state directories if it is
// absent, and refuses one that anybody else could have interfered with. Both the
// locks (#161) and the authorized_keys backups (#228) depend on living somewhere the
// account they concern cannot reach.
func ensureBrokerOwnedDir(what, dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
				return fmt.Errorf("failed to create %s %q: %w", what, dir, mkErr)
			}
			return nil
		}
		return fmt.Errorf("failed to stat %s %q: %w", what, dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use %s %q: it is a symlink", what, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to use %s %q: it is not a directory", what, dir)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("refusing to use %s %q: mode %#o is writable by group or other",
			what, dir, info.Mode().Perm())
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("refusing to use %s %q: it is owned by uid %d, not by this process (uid %d)",
			what, dir, stat.Uid, os.Geteuid())
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
	exists, err := checkSSHDir(sshDir, account)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if mkErr := os.MkdirAll(sshDir, 0700); mkErr != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", mkErr)
	}
	return chownDirToAccount(sshDir, account)
}

// checkSSHDir is the half of ensureSecureSSHDir that creates nothing: it reports
// whether .ssh exists, and refuses one that is a symlink, is not a directory, or
// belongs to a third account. A .ssh that is simply absent is not an error — the
// account has never had a key — so callers that only remove or read return early
// rather than bringing a directory into existence on a cleanup pass.
//
// (#204) Every entry point goes through this now, and four of them went through
// nothing. RemovePublicKey and RemoveExpiredKeys used os.Stat(sshDir) purely to ask
// whether it existed — os.Stat *follows* symlinks, so `ln -s /root/.ssh ~/.ssh`
// answered yes — and KeyIsAuthorized and ListOIDCKeys did not look at .ssh at all.
// Nothing further stopped them: authorized_keys inside the linked directory is not
// itself a symlink, so rejectIfSymlink passes it, O_NOFOLLOW constrains only the
// final component, and the descriptor's owner is root, which checkOwner accepts
// because sshd's StrictModes accepts it. So RemoveExpiredKeys and RemovePublicKey
// rewrote root's key list through a bob-owned temp file, and ListOIDCKeys and
// KeyIsAuthorized read it out — with no race to win, because the link can be planted
// before the call and nothing looked.
//
// This closes the no-race half. It does not make the check race-free: it is a name
// being validated and then used, and the fix for that is to hold the home open and
// perform every subsequent operation with openat(2) relative to a verified .ssh
// descriptor, which is a larger change than this. What is left is a window an
// attacker must win, rather than a door standing open.
func checkSSHDir(sshDir string, account Account) (bool, error) {
	info, err := os.Lstat(sshDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to stat .ssh directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("refusing to use .ssh: %q is a symlink", sshDir)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("refusing to use .ssh: %q is not a directory", sshDir)
	}
	if err := checkOwner(".ssh directory", sshDir, info, account); err != nil {
		return false, err
	}
	return true, nil
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
	file, info, err := openRegularFileForRead(path, "authorized_keys")
	if err != nil {
		return nil, err
	}
	if file == nil {
		return nil, nil // no file, so no keys: the normal case for a new account
	}
	defer func() { _ = file.Close() }()

	if err := checkOwner("authorized_keys", path, info, account); err != nil {
		return nil, err
	}
	data, err := readAtMost(file, path, "authorized_keys", info.Size())
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n"), nil
}

// openRegularFileForRead opens a file the broker is about to read out of a directory
// the target account controls, and returns it only if what was opened is a regular
// file. A missing file yields (nil, nil, nil), because for authorized_keys and for a
// backup that is an answer rather than a failure.
//
// (#205) Two things here, and the order of them is the point.
//
// O_NONBLOCK: the open used to be plain O_RDONLY|O_NOFOLLOW, and open(2) on a FIFO
// opened for reading blocks until a writer appears. `rm ~/.ssh/authorized_keys &&
// mkfifo ~/.ssh/authorized_keys` therefore parked the caller in the kernel forever —
// measured on this host: an os.OpenFile with those exact flags on a FIFO had not
// returned after two seconds, while the same open with O_NONBLOCK returned
// immediately. That block happens inside withFileLock, so the per-user lock is held
// for the duration, and it happens on the broker's single session-cleanup goroutine,
// so no session expires and no key is revoked *for any account on the host* again,
// and Stop() hangs on wg.Wait() until systemd's TimeoutStopSec fires. It is #161
// reached through a different door: the lock is safe now, but the critical section
// could still be blocked from inside it.
//
// The fstat is on the descriptor, not the path: rejectIfSymlink only tells us what
// the name pointed at a moment ago, and it tests os.ModeSymlink alone, so a FIFO
// passed it (confirmed: Lstat of a FIFO reports mode prw------- with ModeSymlink
// clear and IsRegular false). Checking the mode of what was actually opened closes
// the check-then-use gap rather than widening the check — whatever the name was
// swapped for in between, this is the object the read will come from.
func openRegularFileForRead(path, what string) (*os.File, os.FileInfo, error) {
	if err := rejectIfSymlink(path); err != nil {
		return nil, nil, err
	}
	// #nosec G304 -- path is <resolved home>/.ssh/<name> for a validated login name, or
	// a file in the broker's own state directory; symlink-checked above, opened
	// O_NOFOLLOW so the final component cannot be a link, O_NONBLOCK so a FIFO cannot
	// wedge the open, and refused below unless the descriptor is a regular file.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("failed to open %s file: %w", what, err)
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("failed to stat the open %s file: %w", what, err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("refusing to read %s %q: it is not a regular file (mode %s)",
			what, path, info.Mode())
	}
	return file, info, nil
}

// readAtMost reads a whole file that has already been shown to be a regular one,
// refusing anything larger than maxAuthorizedKeysBytes (#206).
//
// The size is checked twice on purpose. The fstat size is what makes an absurd file
// cheap to refuse — nothing is allocated for a 200 GB sparse file — but the file lives
// in a directory the account can write, so it can grow between the fstat and the
// read. The LimitReader is what bounds the allocation whatever the fstat said, and
// reaching the limit is an error rather than a truncation: a key list silently missing
// its tail would be written straight back out by the caller.
func readAtMost(file *os.File, path, what string, size int64) ([]byte, error) {
	if size > maxAuthorizedKeysBytes {
		return nil, fmt.Errorf("refusing to read %s %q: it is %d bytes, and anything over %d "+
			"is not a key list", what, path, size, maxAuthorizedKeysBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAuthorizedKeysBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read %s file: %w", what, err)
	}
	if len(data) > maxAuthorizedKeysBytes {
		return nil, fmt.Errorf("refusing to read %s %q: it grew past %d bytes while being read",
			what, path, maxAuthorizedKeysBytes)
	}
	return data, nil
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
	handOver, err := targetShouldBeHandedToAccount(path, account)
	if err != nil {
		return err
	}

	// (#225) The temp file used to be named .authorized_keys.tmp.<pid>. The broker's
	// pid is readable by any local user — /proc, ps, systemd's MainPID — and the
	// directory belongs to the target account, so the account could pre-create that
	// exact name as a directory, as a symlink, or as a file it holds, and every write
	// through this function failed. The name is keyed on the broker's pid and nothing
	// else, so the account obstructing it need not be the account being provisioned:
	// one user could stop key provisioning for the whole host. Two brokers, or a pid
	// recycled after a crash, collided on it by accident for the same reason.
	//
	// os.CreateTemp picks an unpredictable name and creates it O_EXCL, retrying on
	// collision, so there is no name to pre-create and nothing to clobber: O_EXCL on
	// an existing name — including a symlink, dangling or not — fails rather than
	// following it.
	tmp, err := os.CreateTemp(sshDir, ".authorized_keys.tmp.*")
	if err != nil {
		return fmt.Errorf("failed to create temp authorized_keys: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("failed to write temp authorized_keys: %w", err)
	}
	// The handover goes through the still-open descriptor rather than through
	// tmpPath (#203). The temp file sits in a directory the account can write, so a
	// chown by name could be pointed at any file on the host. fchown(2) can only reach
	// the file that was opened here.
	if handOver {
		if err := chownFileToAccount(tmp, account); err != nil {
			_ = tmp.Close()
			cleanup()
			return err
		}
	}
	// (#225) fsync before the rename. Without it, on ext4 with the default
	// data=ordered, a host that loses power just after the rename can come back with
	// the directory entry durable and the file's contents not — the documented outcome
	// is a zero-length authorized_keys. Every provisioned key for that account is then
	// gone, and nothing detects it, because the file exists and parses: the user simply
	// cannot log in by the mechanism the broker is responsible for until their next
	// successful login rewrites it.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("failed to flush temp authorized_keys to disk: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("failed to close temp authorized_keys: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("failed to replace authorized_keys: %w", err)
	}
	syncDir(sshDir)
	return nil
}

// syncDir fsyncs a directory so that a rename into it survives a crash.
//
// (#225) The second half of the atomic-replace recipe: fsync on the file makes the
// contents durable, fsync on the directory makes the *name* pointing at them durable.
// Without it a crash can leave the account with the previous key list, which is at
// least a consistent state, but the rename's durability is unspecified.
//
// A failure here is logged and not returned. The rename has already happened, so the
// running system is correct and there is nothing to undo; reporting an error would
// tell AddPublicKey's caller that provisioning failed when it had succeeded, and deny
// a login over a durability warning. It is also not something a retry fixes.
func syncDir(dir string) {
	// #nosec G304 -- dir is the .ssh directory this write has already validated, opened
	// O_NOFOLLOW|O_DIRECTORY so it cannot be redirected to anything else.
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		log.Warn().Err(err).Str("dir", dir).
			Msg("Could not open the .ssh directory to flush it; the authorized_keys replacement " +
				"may not survive a crash")
		return
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		log.Warn().Err(err).Str("dir", dir).
			Msg("Could not flush the .ssh directory; the authorized_keys replacement may not " +
				"survive a crash")
	}
}

// targetShouldBeHandedToAccount reports whether the replacement for path should be
// given to the account, or left owned by the broker.
//
// (#228) chownFileToAccount used to run on every write, whoever owned the file before
// it. A root-owned authorized_keys — a hardened deployment, an operator who wrote the
// file with sudo, a configuration-management system that owns it — was therefore
// handed to the unprivileged account by the broker's first write. Nothing looked
// wrong afterwards: the contents were correct, and the only visible change was that
// the user could now edit the list of keys that authorize them, which is exactly what
// root ownership was there to prevent. sshd is content either way; StrictModes
// accepts an authorized_keys owned by the target user or by root, provided it is not
// group- or world-writable, and this function writes 0600.
//
// (#171 still holds for the other direction: a file the broker created in someone's
// home must end up theirs, or they cannot manage their own keys.) So the rule is that
// the broker hands over what it created and preserves what it found.
//
// The existing owner is read with Lstat rather than through a descriptor, and that is
// sound here even though the directory is user-writable. The chown itself still goes
// through the temp file's own descriptor, so a swapped name cannot redirect it; the
// only thing a race can change is the *decision*, and both wrong answers are safe.
// Deciding to keep root ownership when the file was in fact the user's leaves them a
// root-owned key list they cannot edit — visible, and not a privilege gain. Deciding
// to hand over when the file was in fact root-owned requires the attacker to have
// replaced a root-owned authorized_keys with one of their own first, which means .ssh
// was writable by them, which means root ownership of the file was not protecting
// anything to begin with.
func targetShouldBeHandedToAccount(path string, account Account) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil // the broker is creating it, so it is the broker's to give
		}
		return false, fmt.Errorf("failed to stat authorized_keys: %w", err)
	}
	uid, ok := statUID(info)
	if !ok {
		return false, fmt.Errorf("cannot determine the owner of authorized_keys %q", path)
	}
	return uid == account.UID, nil
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
	backupDir     string
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
		// Backups live beside the locks, in the broker's own state directory, and never
		// in the user's .ssh (#228). Derived from lockDir rather than hardcoded so that
		// a manager pointed at a temporary state directory keeps everything there:
		// production's /var/lib/oidc-pam/locks yields /var/lib/oidc-pam/backups.
		backupDir:   filepath.Join(filepath.Dir(lockDir), "backups"),
		lockTimeout: lockAcquireTimeout,
		keyLifetime: DefaultKeyLifetime,
	}
}

// SetBackupDir overrides where BackupAuthorizedKeys writes and RestoreAuthorizedKeys
// reads. It must be a directory only the broker can write to — see BackupAuthorizedKeys
// for why a backup in the user's own .ssh cannot be trusted as a restore source.
func (akm *AuthorizedKeysManager) SetBackupDir(dir string) {
	if dir != "" {
		akm.backupDir = dir
	}
}

// BackupPath returns the file BackupAuthorizedKeys writes for an account.
func (akm *AuthorizedKeysManager) BackupPath(username string) string {
	return filepath.Join(akm.backupDir, username+".authorized_keys")
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

// LockPath returns the lock file serializing writes to the authorized_keys file
// this account's home directory resolves to.
//
// (#225) The lock used to be named after the account: <lockDir>/<username>.lock. Two
// accounts can share a home directory — a deliberate configuration for a pair of
// service identities, and also what an NSS or LDAP misconfiguration produces — and
// two writers naming their locks after different accounts do not exclude each other
// even though they are rewriting the same file. Both read, both write, the second
// rename wins, and one account's key has silently vanished from a file that looks
// perfectly well-formed. Keying the lock on the directory instead means anything
// writing a given authorized_keys takes the same lock, whichever account it is for.
//
// The name is a hash because the thing being named is a path, which does not fit in a
// filename and cannot be sanitized into one without making two different paths
// collide. An operator can recover the mapping with
// `printf %s /home/bob/.ssh | sha256sum` and comparing the first 32 characters.
//
// This is textual, not canonical: a path is not resolved through symlinks first.
// Resolving would have to happen before .ssh exists, which is exactly when it cannot
// be resolved, and a fallback that sometimes resolves and sometimes does not would
// hand two writers of the same file two different lock names — the bug this fixes.
// So two aliases of one directory (a symlinked component above .ssh) still take
// different locks. userPaths refuses a symlinked home and checkSSHDir a symlinked
// .ssh, so reaching that needs an operator to have aliased an intermediate directory,
// and the atomic replace still leaves a consistent file; what can be lost is one
// concurrent update.
func (akm *AuthorizedKeysManager) LockPath(username string) string {
	account, err := akm.lookupAccount(username)
	if err != nil {
		// A name that does not resolve never reaches a write — userPaths fails first —
		// so this value guards nothing. It is still distinct per name, so that a caller
		// holding it cannot accidentally exclude an unrelated account.
		return akm.lockPathForKey("unresolved-account\x00" + username)
	}
	return akm.lockPathForSSHDir(filepath.Join(account.Home, ".ssh"))
}

// lockPathForSSHDir is what the write paths actually lock on: the .ssh directory they
// are about to write into. See LockPath.
func (akm *AuthorizedKeysManager) lockPathForSSHDir(sshDir string) string {
	return akm.lockPathForKey(filepath.Clean(sshDir))
}

func (akm *AuthorizedKeysManager) lockPathForKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(akm.lockDir, hex.EncodeToString(sum[:16])+".lock")
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

// AddPublicKey installs the broker's key in a user's authorized_keys, carrying the
// expiry sshd will enforce on it, alongside the entries the account's other live
// sessions are using.
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
//     the others in place. What bounds that now is the expiry on every entry, the
//     removal of expired entries below, and maxConcurrentOIDCKeys — not the removal
//     of entries that still belong to a live session, which is what #227 undid.
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

	// (#199) Nothing below this point can tell whether the host's sshd will honour the
	// entry it is about to write. The entry carries `expiry-time=`, and an sshd older
	// than minOpenSSHVersion does not ignore an option it does not know — it refuses
	// the whole entry. So on such a host every write here succeeded, the file looked
	// correct, the broker reported the login as successful, and the user was then told
	// `Permission denied (publickey)` by sshd with nothing recording why. Refusing
	// before anything is written turns that into one error, on the login that caused
	// it, naming the version found and the version needed. See sshdSupportsKeyExpiry
	// for why an undetermined version is not refused.
	if err := sshdSupportsKeyExpiry(); err != nil {
		return err
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

	return withFileLock(akm.lockPathForSSHDir(sshDir), akm.lockTimeout, func() error {
		existing, err := readAuthorizedKeysLines(authorizedKeysPath, account)
		if err != nil {
			return err
		}

		plan := akm.planInstall(existing, newEntry, time.Now())
		if plan.evicted > 0 {
			// The only case in which this write takes a key a live session may still be
			// using, so it is said out loud: whoever is holding that session will see its
			// next connection refused, and this line is the only thing that explains it.
			log.Warn().
				Str("username", username).
				Int("evicted_keys", plan.evicted).
				Int("limit", maxConcurrentOIDCKeys).
				Msg("Dropped the oldest broker-issued keys to stay within the per-account limit; " +
					"sessions holding them cannot open new connections")
		}
		kept := append(plan.kept,
			fmt.Sprintf("%s %s", brokerCommentPrefix, time.Now().Format("2006-01-02 15:04:05")),
			brokerEntryLine(publicKey, expiresAt))

		if err := writeAuthorizedKeysLines(sshDir, authorizedKeysPath, kept, account); err != nil {
			return fmt.Errorf("failed to write authorized_keys file: %w", err)
		}

		log.Info().
			Str("username", username).
			Str("authorized_keys_path", authorizedKeysPath).
			Int("replaced_keys", plan.replaced).
			Int("expired_keys", plan.expired).
			Int("evicted_keys", plan.evicted).
			Int("other_live_keys", plan.retained).
			Time("expires_at", expiresAt).
			Msg("Public key added to authorized_keys")

		return nil
	})
}

// maxConcurrentOIDCKeys is how many broker-issued entries one account may hold at
// once, and so how many of its sessions can be authorized at the same time.
//
// (#227) There used to be one, because an install dropped every broker-issued entry it
// found before writing its own. That is the ordinary case for anyone with more than one
// machine: a user logged in from their laptop and then from a jump host, and the second
// login removed the key the first session was using. The laptop's open connection
// survived — sshd had already authenticated it — but the next connection was refused,
// and so was the reconnect a ControlMaster re-dial or a resumed laptop makes, while the
// broker went on reporting that session as live and unexpired. Nothing in the file, the
// log or the audit trail said the key had been taken away.
//
// "Never evict" is not the answer either. Every login mints a key, so a user who logs
// in hourly — or a script that logs in in a loop — would grow authorized_keys without
// limit, and the growth ends somewhere much worse than an untidy file: past
// maxAuthorizedKeysBytes the broker refuses to read the file at all, at which point no
// login can be provisioned and no sweep can remove anything for that account until an
// operator edits it by hand.
//
// Sixteen because it is well beyond the number of sessions a person holds at once — a
// workstation, a laptop, a phone, a handful of jump hosts, each re-authenticating a few
// times a day — while bounding the broker's own entries to about two kilobytes. Beyond
// that the account is in a login loop rather than in use, and the newest key is the one
// worth keeping.
const maxConcurrentOIDCKeys = 16

// installPlan is what an install decides about the lines already in authorized_keys:
// the ones that survive it, and a count of each reason the others did not, so that the
// install can say in its log what it took away.
type installPlan struct {
	kept     []string
	replaced int // this very entry, being rewritten with the current expiry
	expired  int // broker entries sshd has already stopped honouring
	evicted  int // live broker entries dropped to stay within maxConcurrentOIDCKeys
	retained int // broker entries carried through, belonging to the account's other sessions
}

// planInstall works out which of an account's existing authorized_keys lines survive
// an install. The new entry is not in the plan: the caller appends it.
//
// The rules, in the order they are applied to each line:
//
//   - A line that is not an entry the broker installed is kept, whatever it
//     authorizes. A key the user put there themselves is none of the broker's
//     business.
//   - The entry being installed, if it is already in the file, is dropped, because the
//     line about to be appended is the same entry carrying the current expiry.
//   - A broker entry whose expiry has passed is dropped. sshd stopped honouring it
//     already, and an install is a chance to tidy the file without waiting for
//     RemoveExpiredKeys to reach this account — which only happens when some session
//     of this user's expires (see the broker's sweepExpiredAuthorizedKeys).
//   - Every remaining broker entry belongs to one of the account's other sessions and
//     is kept (#227), up to maxConcurrentOIDCKeys.
func (akm *AuthorizedKeysManager) planInstall(existing []string, newEntry keyEntry, now time.Time) installPlan {
	plan := installPlan{kept: make([]string, 0, len(existing)+2)}

	// Which entry to evict cannot be decided a line at a time — it depends on how the
	// live entries compare with each other — so the first pass only classifies.
	type liveEntry struct {
		index    int
		deadline time.Time
		dated    bool
	}
	drop := make(map[int]bool, len(existing))
	live := make([]liveEntry, 0, len(existing))
	for i, line := range existing {
		entry, isEntry := parseKeyEntry(line)
		if !isEntry {
			continue
		}
		if entry.isSameEntryAs(newEntry) {
			drop[i] = true
			plan.replaced++
			continue
		}
		if !entry.brokerIssued() {
			continue
		}
		deadline, dated := akm.entryDeadline(entry)
		if dated && now.After(deadline) {
			drop[i] = true
			plan.expired++
			continue
		}
		live = append(live, liveEntry{index: i, deadline: deadline, dated: dated})
	}

	// The entry being installed takes one of the slots, so the existing ones may fill
	// the rest. The nearest to its expiry goes first: it is the session closest to
	// ending anyway, and evicting the one with the longest left would take a key that
	// had the most use still in it.
	if excess := len(live) - (maxConcurrentOIDCKeys - 1); excess > 0 {
		sort.SliceStable(live, func(a, b int) bool {
			if live[a].dated != live[b].dated {
				// An entry carrying the broker's marker whose expiry cannot be read
				// either way goes first. RemoveExpiredKeys deliberately retains such an
				// entry — cleanup fails safe, never early — so if it also outranked keys
				// known to be live here, a handful of mangled or hand-written lines would
				// hold the limit permanently and evict every real session's key instead.
				return !live[a].dated
			}
			return live[a].deadline.Before(live[b].deadline)
		})
		for _, victim := range live[:excess] {
			drop[victim.index] = true
			plan.evicted++
		}
		live = live[excess:]
	}
	plan.retained = len(live)

	for i, line := range existing {
		if _, isEntry := parseKeyEntry(line); isEntry && drop[i] {
			continue
		}
		plan.kept = append(plan.kept, line)
	}
	// A dropped entry leaves its provenance comment behind, and with several entries in
	// the file that comment would go on to claim a date for whichever one follows it.
	plan.kept = pruneBrokerComments(plan.kept)
	return plan
}

// entryDeadline returns the moment a broker-issued entry stops authorizing anything,
// and whether that could be determined at all.
//
// It is the entry's own `expiry-time=` option where there is one, because that is what
// sshd itself honours, and for an entry written by a broker from before that option the
// issue time in the comment plus the configured lifetime (SetKeyLifetime). An entry
// that says neither yields false, and every caller treats that as an entry it cannot
// make claims about.
func (akm *AuthorizedKeysManager) entryDeadline(entry keyEntry) (time.Time, bool) {
	if expiry, ok := entry.expiryTime(); ok {
		return expiry, true
	}
	if issued, ok := entry.issuedAt(); ok {
		return issued.Add(akm.keyLifetime), true
	}
	return time.Time{}, false
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

	// Validate .ssh rather than merely asking whether it exists (#204): os.Stat
	// followed a symlinked .ssh, and this path then rewrote whatever it pointed at.
	// An absent .ssh still means there is nothing to remove.
	sshDirExists, err := checkSSHDir(sshDir, account)
	if err != nil {
		return false, err
	}
	if !sshDirExists {
		return false, nil
	}

	target, ok := parseKeyEntry(string(publicKey))
	if !ok {
		return false, fmt.Errorf("public key is not a valid authorized_keys entry")
	}

	removed := false
	err = withFileLock(akm.lockPathForSSHDir(sshDir), akm.lockTimeout, func() error {
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
			pruneBrokerComments(filteredLines), account); err != nil {
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
	account, sshDir, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return false, err
	}
	target, ok := parseKeyEntry(string(publicKey))
	if !ok {
		return false, fmt.Errorf("public key is not a valid authorized_keys entry")
	}

	// (#204) This used not to look at .ssh at all, so a symlinked .ssh made it report
	// on somebody else's key list — root's, if it was aimed at /root/.ssh, which
	// checkOwner accepts. The answer feeds the broker's decision about whether a
	// revocation that matched nothing is benign, so a wrong answer there is an alarm
	// about the wrong account.
	sshDirExists, err := checkSSHDir(sshDir, account)
	if err != nil {
		return false, err
	}
	if !sshDirExists {
		return false, nil
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

	// An absent .ssh means there is nothing to reconcile; a symlinked one is refused
	// rather than followed (#204).
	sshDirExists, err := checkSSHDir(sshDir, account)
	if err != nil {
		return 0, err
	}
	if !sshDirExists {
		return 0, nil
	}

	removed := 0
	err = withFileLock(akm.lockPathForSSHDir(sshDir), akm.lockTimeout, func() error {
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
		return writeAuthorizedKeysLines(sshDir, authorizedKeysPath, pruneBrokerComments(kept), account)
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

	// Validate .ssh rather than merely asking whether it exists (#204). This is the
	// path the broker's single cleanup goroutine walks for every account on the host,
	// and os.Stat followed a symlinked .ssh straight into whatever it named.
	sshDirExists, err := checkSSHDir(sshDir, account)
	if err != nil {
		return err
	}
	if !sshDirExists {
		return nil
	}

	return withFileLock(akm.lockPathForSSHDir(sshDir), akm.lockTimeout, func() error {
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
			pruneBrokerComments(filteredLines), account); err != nil {
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
	deadline, dated := akm.entryDeadline(entry)
	return dated && now.After(deadline)
}

// ListOIDCKeys lists all OIDC PAM keys in a user's authorized_keys file.
//
// Operator-facing: nothing in the authentication path calls this. It exists so
// that an administrator investigating a user's access can see which
// authorized_keys entries this broker is responsible for, distinguished from the
// user's own keys by the `@oidc-pam-<timestamp>` comment.
func (akm *AuthorizedKeysManager) ListOIDCKeys(username string) ([]string, error) {
	account, sshDir, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return nil, err
	}

	// (#204) Also did not look at .ssh. An operator asking which entries the broker
	// owns for an account must not be shown the contents of a key list the account
	// merely symlinked to.
	sshDirExists, err := checkSSHDir(sshDir, account)
	if err != nil {
		return nil, err
	}
	if !sshDirExists {
		return []string{}, nil
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

// BackupAuthorizedKeys creates a backup of the authorized_keys file, in the broker's
// own state directory.
//
// Operator-facing recovery API, paired with RestoreAuthorizedKeys; the broker
// does not call it during authentication. The key-management functions rewrite a
// file the user also owns, so a copy taken before a manual intervention is worth
// having.
//
// (#228) The backup used to be written to ~/.ssh/authorized_keys.backup and chowned
// to the account, which made it useless as a recovery source and worse than useless
// as a restore source. It was user-owned and user-writable, sitting in a directory
// the user controls under a name they can predict, so the user could rewrite it and
// then have the broker install its contents with root's privileges; and a backup of a
// root-owned authorized_keys became user-owned by the act of backing it up. A copy
// somebody can edit is not a backup of anything. It now lives in the broker's state
// directory, mode 0700, and is never handed over.
func (akm *AuthorizedKeysManager) BackupAuthorizedKeys(username string) error {
	account, sshDir, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return err
	}
	sshDirExists, err := checkSSHDir(sshDir, account)
	if err != nil {
		return err
	}
	if !sshDirExists {
		return nil // nothing to back up
	}
	if _, statErr := os.Lstat(authorizedKeysPath); os.IsNotExist(statErr) {
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

	if err := ensureBrokerOwnedDir("backup directory", akm.backupDir); err != nil {
		return err
	}
	backupPath := akm.BackupPath(username)
	// #nosec G304 -- <backupDir>/<validated login name>.authorized_keys, in a directory
	// ensureBrokerOwnedDir has just checked only this process can write; O_NOFOLLOW so
	// that even there the final component cannot be a link.
	bf, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	if _, err := bf.Write(data); err != nil {
		_ = bf.Close()
		return fmt.Errorf("failed to create backup: %w", err)
	}
	if err := bf.Sync(); err != nil {
		_ = bf.Close()
		return fmt.Errorf("failed to flush backup to disk: %w", err)
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
	account, sshDir, authorizedKeysPath, err := akm.userPaths(username)
	if err != nil {
		return err
	}
	backupPath := akm.BackupPath(username)

	// The backup is read the same way authorized_keys is: bounded, and only if the
	// descriptor turns out to be a regular file. It is in the broker's own directory
	// now (#228), so neither guard should ever fire — but this is the one path that
	// writes a file's contents into an account's key list with root's privileges, and
	// it is not the place to assume a directory is beyond reach.
	bf, info, err := openRegularFileForRead(backupPath, "backup")
	if err != nil {
		return err
	}
	if bf == nil {
		return fmt.Errorf("no backup file found at %s", backupPath)
	}
	data, err := readAtMost(bf, backupPath, "backup", info.Size())
	_ = bf.Close()
	if err != nil {
		return err
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
