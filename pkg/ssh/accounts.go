package ssh

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Account is what the broker has to know about a local account before it writes
// into that account's ~/.ssh: where the home directory really is, and who owns it.
//
// (#171) Both facts used to be assumed. The broker joined "/home" with the login
// name and wrote there, so on any site whose homes are not literally /home/<user>
// — LDAP/SSSD with /home/<domain>/<user>, autofs, NFS, a home moved by hand — it
// wrote an authorized_keys sshd never reads, reported success, and let the login
// through with no working key. The uid was never looked at at all, so the same
// code would happily create /home/<user> itself, root-owned and mode 0700, and
// lock a user out of their own home directory.
type Account struct {
	// Username is the login name as resolved, echoed back so a caller logging an
	// Account does not have to carry the name separately.
	Username string
	// Home is the account's home directory from the passwd database. It is used as
	// given: this package never derives, guesses or creates it.
	Home string
	UID  int
	GID  int
}

// AccountLookup resolves a local login name to its passwd entry.
//
// It is a function type so that the manager's dependency on the host's account
// database is explicit and substitutable — production uses LookupAccount, tests
// present a table of their own (see HomeRootLookup).
type AccountLookup func(username string) (Account, error)

// ErrUnknownAccount is returned when the login name has no passwd entry. It is
// distinct because "this account does not exist" is a configuration or
// identity-mapping problem an operator can act on, while any other lookup error
// is a fault in the account database.
var ErrUnknownAccount = errors.New("no such local account")

// getentPath is the program consulted when os/user cannot answer. Overridden by
// tests; see lookupViaGetent.
var getentPath = "/usr/bin/getent"

// getentTimeout bounds the fallback lookup. A wedged NSS backend must not hold a
// login open until sshd's LoginGraceTime kills it. A variable so the test for that
// does not have to wait out the production value.
var getentTimeout = 5 * time.Second

// LookupAccount resolves an account through the host's account database. This is
// the production AccountLookup.
//
// It asks os/user first and falls back to getent(1). The fallback is not
// belt-and-braces: the released broker is built with CGO_ENABLED=0
// (.github/workflows/release.yml), and without cgo os/user does not go through
// NSS at all — it parses /etc/passwd directly. Every account that comes from
// SSSD, LDAP or any other NSS source is therefore invisible to it, which is
// precisely the population #171 is about. getent asks NSS the same way sshd and
// login do, so the broker resolves the same home directory they do.
func LookupAccount(username string) (Account, error) {
	if err := validateUsername(username); err != nil {
		return Account{}, err
	}

	usr, err := user.Lookup(username)
	if err == nil {
		return accountFromStrings(username, usr.HomeDir, usr.Uid, usr.Gid)
	}

	var unknown user.UnknownUserError
	if !errors.As(err, &unknown) {
		return Account{}, fmt.Errorf("failed to look up account %q: %w", username, err)
	}

	account, getentErr := lookupViaGetent(username)
	if getentErr == nil {
		return account, nil
	}
	if errors.Is(getentErr, ErrUnknownAccount) {
		return Account{}, fmt.Errorf("%w: %q", ErrUnknownAccount, username)
	}
	return Account{}, fmt.Errorf("failed to look up account %q via getent: %w", username, getentErr)
}

// lookupViaGetent reads one passwd entry through NSS.
//
// The username is validated by every caller before it gets here, and is passed as
// a separate argument to an absolute program path — there is no shell, so no
// quoting question.
func lookupViaGetent(username string) (Account, error) {
	if _, err := os.Stat(getentPath); err != nil {
		return Account{}, fmt.Errorf("%w (getent is unavailable at %s)", ErrUnknownAccount, getentPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), getentTimeout)
	defer cancel()

	// #nosec G204 -- getentPath is a fixed absolute path (a test hook, not
	// configuration) and username has passed validateUsername, which admits only
	// POSIX login names.
	cmd := exec.CommandContext(ctx, getentPath, "passwd", username)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	// The context alone does not bound this. Killing getent does not close the pipe
	// its output is read through if getent has forked a child that inherited it, and
	// Output waits for the pipe, not the process — so a wedged NSS backend could
	// still hold the lookup open for as long as that child lived. WaitDelay makes the
	// wait give up and close the pipes.
	cmd.WaitDelay = getentTimeout

	out, runErr := cmd.Output()
	if ctx.Err() != nil {
		return Account{}, fmt.Errorf("getent passwd %q did not answer within %s", username, getentTimeout)
	}
	if runErr != nil {
		// getent exits 2 for "key not found", which is an answer, not a failure.
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) && exitErr.ExitCode() == 2 {
			return Account{}, ErrUnknownAccount
		}
		return Account{}, runErr
	}

	line := strings.TrimSpace(string(out))
	if line == "" {
		return Account{}, ErrUnknownAccount
	}
	// name:passwd:uid:gid:gecos:home:shell
	//
	// (#229) The home directory is taken from the *end* of the line, not from index 5.
	// Only GECOS can legitimately contain a colon — an smbldap- or AD-populated GECOS
	// routinely does, e.g. "Smith, Jane:Engineering" — and getent prints whatever NSS
	// handed it without escaping, so such a line splits into more than seven fields
	// and everything after GECOS shifts right. The count check here is `< 7`, so the
	// line was *accepted*: index 5 then held the tail of the GECOS rather than the
	// home directory, and the broker went on to write an authorized_keys under a path
	// like "Engineering" — or, since userPaths refuses a home that does not exist,
	// denied the login with an error about a home directory nobody had configured.
	//
	// Counting home and shell from the right resolves the ambiguity correctly for any
	// number of colons in GECOS, and is identical to the old behaviour on a well-formed
	// seven-field line. It is wrong only if the *home directory or shell* contains a
	// colon, which no passwd database does.
	fields := strings.Split(strings.SplitN(line, "\n", 2)[0], ":")
	if len(fields) < 7 {
		return Account{}, fmt.Errorf("getent returned a passwd line with %d fields: %q", len(fields), line)
	}
	if fields[0] != username {
		return Account{}, fmt.Errorf("getent answered for %q when asked about %q", fields[0], username)
	}
	home := fields[len(fields)-2]
	return accountFromStrings(username, home, fields[2], fields[3])
}

// accountFromStrings builds an Account from the string fields both lookups
// produce, refusing an entry the broker cannot act on. An empty home directory is
// refused rather than defaulted: a default is how #171 started.
func accountFromStrings(username, home, uid, gid string) (Account, error) {
	if strings.TrimSpace(home) == "" {
		return Account{}, fmt.Errorf("account %q has no home directory in the passwd database", username)
	}
	numericUID, err := strconv.Atoi(uid)
	if err != nil {
		return Account{}, fmt.Errorf("account %q has a non-numeric uid %q", username, uid)
	}
	numericGID, err := strconv.Atoi(gid)
	if err != nil {
		return Account{}, fmt.Errorf("account %q has a non-numeric gid %q", username, gid)
	}
	return Account{Username: username, Home: home, UID: numericUID, GID: numericGID}, nil
}

// HomeRootLookup returns an AccountLookup that places every account's home at
// <root>/<username> and attributes it to the uid and gid this process runs as.
//
// It exists so that tests can exercise the write paths against a temporary tree
// without creating real accounts on the machine running the suite. It is not the
// old behaviour under a new name: production passes LookupAccount, and nothing in
// this package derives a home directory from a base directory any more.
func HomeRootLookup(root string) AccountLookup {
	return func(username string) (Account, error) {
		if err := validateUsername(username); err != nil {
			return Account{}, err
		}
		return Account{
			Username: username,
			Home:     root + string(os.PathSeparator) + username,
			UID:      os.Geteuid(),
			GID:      os.Getegid(),
		}, nil
	}
}

// statUID returns the owning uid of an already-stat'ed file.
func statUID(info fs.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}

// checkOwner refuses a path that belongs to neither the account nor root.
//
// Root is accepted because sshd accepts it: under StrictModes every component of
// the path to authorized_keys must be owned by the target user or by root. A file
// owned by any *third* account is a different matter — someone else can rewrite
// it — and the broker will not read a key list, or write one, through it.
func checkOwner(what, path string, info fs.FileInfo, account Account) error {
	uid, ok := statUID(info)
	if !ok {
		// No Stat_t means an OS this package is not built for; refuse rather than
		// silently skip the check that the rest of the path's safety rests on.
		return fmt.Errorf("cannot determine the owner of %s %q", what, path)
	}
	if uid == account.UID || uid == 0 {
		return nil
	}
	return fmt.Errorf("refusing to use %s %q: it is owned by uid %d, not by %s (uid %d) or root",
		what, path, uid, account.Username, account.UID)
}

// chownFileToAccount gives an already-open descriptor to the account, so that a
// file the root broker created in someone's home stays theirs to manage.
//
// Only root can hand a file to another user, so this is a no-op for an unprivileged
// process — which is every test, and any development run.
//
// (#203) The chown goes through the descriptor, never through a path. os.Chown
// resolves the name it is handed and follows symlinks, and every path this package
// chowns lives in a directory the target account can write. Between creating a file
// and chowning it by name, the account can replace that name with a link to any file
// on the host — /etc/shadow, a setuid binary, root's authorized_keys — and the root
// broker hands them the target. fchown(2) acts on the object that was actually
// opened, so there is no name left to race and no window to race it in.
//
// This is why the fix and CAP_CHOWN (#202) had to land together: until the
// capability was granted every one of these calls failed with EPERM, which made the
// path dead code. Granting the capability without fixing the chown would have
// converted that dead code into a live local privilege escalation.
func chownFileToAccount(f *os.File, account Account) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if err := f.Chown(account.UID, account.GID); err != nil {
		return fmt.Errorf("failed to give %q to %s (uid %d): %w", f.Name(), account.Username, account.UID, err)
	}
	return nil
}

// chownDirToAccount gives a directory to the account without ever following a
// symlink at its path: it opens the directory O_NOFOLLOW|O_DIRECTORY and chowns the
// descriptor. See chownFileToAccount for why the name is not safe to chown.
//
// O_NOFOLLOW constrains only the final path component, which is the component the
// account controls here — the parent is their home directory, verified by the caller.
func chownDirToAccount(path string, account Account) error {
	if os.Geteuid() != 0 {
		return nil
	}
	// #nosec G304 -- path is <resolved home>/.ssh for a validated login name, and the
	// descriptor is refused below unless it is a real directory rather than a link.
	dir, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("failed to open %q to give it to %s: %w", path, account.Username, err)
	}
	defer func() { _ = dir.Close() }()
	return chownFileToAccount(dir, account)
}
