package ssh

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stubGetent replaces the getent(1) the fallback lookup runs with a shell script
// that behaves as the test describes, and restores the real path afterwards.
func stubGetent(t *testing.T, script string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "getent")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0700); err != nil { // #nosec G306 -- must be executable
		t.Fatalf("WriteFile: %v", err)
	}

	previous := getentPath
	getentPath = path
	t.Cleanup(func() { getentPath = previous })
}

// The reason the fallback exists: the released broker is built without cgo, so
// os/user parses /etc/passwd and never asks NSS. An account that only NSS knows
// about — every SSSD or LDAP account — must still resolve, and must resolve to the
// home directory NSS gives, not to /home/<name> (#171).
func TestAnAccountKnownOnlyToNSSResolvesThroughGetent(t *testing.T) {
	stubGetent(t, `
if [ "$1" = passwd ] && [ "$2" = alice ]; then
  echo 'alice:x:4242:4243:Alice Example:/home/ldap-domain/alice:/bin/bash'
  exit 0
fi
exit 2
`)

	account, err := LookupAccount("alice")
	if err != nil {
		// A host that really has a local "alice" would answer from os/user first and
		// never reach the stub; skip rather than fail on someone's laptop.
		if _, lookupErr := user.Lookup("alice"); lookupErr == nil {
			t.Skip("this host has a local alice, so the NSS fallback is not reached")
		}
		t.Fatalf("LookupAccount: %v", err)
	}

	if account.Home != "/home/ldap-domain/alice" {
		t.Errorf("home = %q, want the passwd entry's /home/ldap-domain/alice; a broker that "+
			"assumes /home/<user> writes authorized_keys where sshd will not read it", account.Home)
	}
	if account.UID != 4242 || account.GID != 4243 {
		t.Errorf("uid/gid = %d/%d, want 4242/4243", account.UID, account.GID)
	}
	if account.Username != "alice" {
		t.Errorf("username = %q, want alice", account.Username)
	}
}

// (#229) Only GECOS can legitimately contain a colon, and an smbldap- or
// AD-populated one routinely does ("Smith, Jane:Engineering" is the shape
// smbldap-useradd writes, and AD's description attribute is copied verbatim). getent
// prints what NSS handed it with no escaping, so such an entry splits into more than
// seven fields and everything after GECOS shifts right.
//
// The field count check is `< 7`, so the line was *accepted* and index 5 held the tail
// of the GECOS instead of the home directory. The broker then either wrote an
// authorized_keys under a path named after a department, or — since a home that does
// not exist is refused — denied the login with an error naming a directory no operator
// had ever configured. Home and shell are therefore counted from the right, which is
// unambiguous for any number of colons in GECOS and identical on a well-formed line.
func TestAColonInTheGECOSDoesNotShiftTheHomeDirectory(t *testing.T) {
	for _, tc := range []struct {
		name, gecos string
	}{
		{name: "no colon", gecos: "Alice Example"},
		{name: "one colon", gecos: "Smith, Jane:Engineering"},
		{name: "several colons", gecos: "Jane:Engineering:Floor 3:x1234"},
		{name: "empty", gecos: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubGetent(t, "echo 'alice:x:4242:4243:"+tc.gecos+":/home/ldap-domain/alice:/bin/bash'\nexit 0\n")

			account, err := lookupViaGetent("alice")
			if err != nil {
				t.Fatalf("lookupViaGetent: %v", err)
			}
			if account.Home != "/home/ldap-domain/alice" {
				t.Errorf("home = %q, want /home/ldap-domain/alice: a colon in the GECOS shifted "+
					"the fields, so the broker would write a key list somewhere sshd never reads "+
					"(or refuse the login over a home nobody configured)", account.Home)
			}
			if account.UID != 4242 || account.GID != 4243 {
				t.Errorf("uid/gid = %d/%d, want 4242/4243", account.UID, account.GID)
			}
		})
	}
}

// A line with genuinely too few fields is still a broken answer, not something to
// index into from the right: with six fields, "the second from last" is the GECOS.
func TestATruncatedPasswdLineIsRefused(t *testing.T) {
	stubGetent(t, "echo 'alice:x:4242:4243:Alice:/home/alice'\nexit 0\n")

	if account, err := lookupViaGetent("alice"); err == nil {
		t.Fatalf("a six-field passwd line was accepted, giving home %q", account.Home)
	}
}

// getent exits 2 for "key not found". That is an answer, and it has to be
// distinguishable from a broken account database: one means "no such user", the
// other means the broker cannot tell and must not guess.
func TestAnAccountNothingKnowsAboutIsReportedAsUnknown(t *testing.T) {
	stubGetent(t, "exit 2\n")

	name := "oidc-pam-no-such-account"
	_, err := LookupAccount(name)
	if err == nil {
		t.Fatalf("LookupAccount(%q) succeeded", name)
	}
	if !errors.Is(err, ErrUnknownAccount) {
		t.Errorf("error is %v, want one matching ErrUnknownAccount so callers can tell "+
			"\"no such user\" from \"the account database is broken\"", err)
	}
}

// A getent that never answers — a wedged LDAP backend is the usual cause — must
// not hold the login open. The lookup is bounded, so this returns instead of
// hanging until the test binary's timeout.
func TestAWedgedAccountDatabaseDoesNotHangTheLookup(t *testing.T) {
	stubGetent(t, "sleep 300\n")

	previousTimeout := getentTimeout
	getentTimeout = 200 * time.Millisecond
	t.Cleanup(func() { getentTimeout = previousTimeout })

	name := "oidc-pam-no-such-account"
	if _, err := user.Lookup(name); err == nil {
		t.Skipf("this host has a local %s", name)
	}

	done := make(chan error, 1)
	go func() { _, err := LookupAccount(name); done <- err }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a getent that never answered produced an account")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("LookupAccount did not return; a wedged account database blocks the login " +
			"until sshd's LoginGraceTime kills it")
	}
}

// getent answering about a different account than the one asked about means the
// database is not to be trusted for this decision; the broker must not write into
// whatever home came back.
func TestAnAnswerAboutTheWrongAccountIsRefused(t *testing.T) {
	stubGetent(t, "echo 'root:x:0:0:root:/root:/bin/sh'\nexit 0\n")

	name := "oidc-pam-no-such-account"
	if _, err := user.Lookup(name); err == nil {
		t.Skipf("this host has a local %s", name)
	}

	account, err := LookupAccount(name)
	if err == nil {
		t.Fatalf("LookupAccount accepted an answer about %q, returning home %q",
			account.Username, account.Home)
	}
}

// The passwd fields the broker cannot act on. An empty home is refused rather than
// defaulted, because defaulting it is exactly how #171 started.
func TestPasswdEntriesTheBrokerCannotActOnAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name             string
		home, uid, gid   string
		wantSubstringErr string
	}{
		{name: "no home directory", home: "", uid: "1000", gid: "1000", wantSubstringErr: "no home directory"},
		{name: "blank home directory", home: "   ", uid: "1000", gid: "1000", wantSubstringErr: "no home directory"},
		{name: "non-numeric uid", home: "/home/alice", uid: "alice", gid: "1000", wantSubstringErr: "non-numeric uid"},
		{name: "non-numeric gid", home: "/home/alice", uid: "1000", gid: "staff", wantSubstringErr: "non-numeric gid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := accountFromStrings("alice", tc.home, tc.uid, tc.gid)
			if err == nil {
				t.Fatalf("accountFromStrings(home=%q, uid=%q, gid=%q) succeeded", tc.home, tc.uid, tc.gid)
			}
			if !strings.Contains(err.Error(), tc.wantSubstringErr) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantSubstringErr)
			}
		})
	}
}

// A negative uid is what a passwd entry with a wrapped or bogus id looks like, and
// it must not become an ownership check that passes by accident.
func TestAnAccountResolvesToTheUIDInTheDatabase(t *testing.T) {
	account, err := accountFromStrings("alice", "/home/alice", "0", "0")
	if err != nil {
		t.Fatalf("accountFromStrings: %v", err)
	}
	if account.UID != 0 {
		t.Errorf("uid = %d, want 0", account.UID)
	}
}

// The lookup must not be handed a name that is not a login name at all: "../.."
// resolving to a home directory is a path-traversal write into someone else's tree.
func TestLookupRefusesSomethingThatIsNotALoginName(t *testing.T) {
	for _, name := range []string{"", "../../etc", "root/../alice", "alice\nbob", "-alice"} {
		if _, err := LookupAccount(name); err == nil {
			t.Errorf("LookupAccount(%q) succeeded; it is not a POSIX login name", name)
		}
	}
}

// checkOwner is what stands between the broker and a home directory someone else
// controls. sshd's own StrictModes accepts the user or root and nothing else, so
// this must too.
func TestOwnershipAcceptsTheAccountAndRootAndNobodyElse(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	owner, ok := statUID(info)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform")
	}

	// Owned by the account: accepted.
	if err := checkOwner("home directory", dir, info, Account{Username: "alice", UID: owner}); err != nil {
		t.Errorf("a path owned by the account was refused: %v", err)
	}

	// Owned by somebody else entirely: refused. This is the case that matters —
	// following it means writing a key list a third party can rewrite.
	stranger := Account{Username: "alice", UID: owner + 1}
	err = checkOwner("home directory", dir, info, stranger)
	if err == nil {
		t.Error("a path owned by a third account was accepted")
	} else if !strings.Contains(err.Error(), strconv.Itoa(owner)) {
		t.Errorf("the refusal does not say who owns the path: %v", err)
	}

	// Owned by root: accepted, because sshd accepts it.
	rootInfo, err := os.Lstat("/")
	if err != nil {
		t.Fatalf("Lstat /: %v", err)
	}
	if uid, ok := statUID(rootInfo); !ok || uid != 0 {
		t.Skip("/ is not owned by root on this host")
	}
	if err := checkOwner("home directory", "/", rootInfo, stranger); err != nil {
		t.Errorf("a root-owned path was refused, but sshd's StrictModes accepts one: %v", err)
	}
}

// HomeRootLookup is a test seam, and the thing it must not do is what the defect
// did: bring a directory into existence.
func TestHomeRootLookupCreatesNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "homes")

	account, err := HomeRootLookup(root)("alice")
	if err != nil {
		t.Fatalf("HomeRootLookup: %v", err)
	}
	if want := filepath.Join(root, "alice"); account.Home != want {
		t.Errorf("home = %q, want %q", account.Home, want)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("looking an account up created %q (Stat error: %v)", root, err)
	}
	if account.UID != os.Geteuid() {
		t.Errorf("uid = %d, want this process's %d", account.UID, os.Geteuid())
	}
}

// A last guard on the fallback's own preconditions: with no getent on the host,
// an account os/user cannot see is unknown rather than a hard error, so the caller
// still gets an actionable message.
func TestAMissingGetentLeavesTheAccountUnknown(t *testing.T) {
	previous := getentPath
	getentPath = filepath.Join(t.TempDir(), "no-getent-here")
	t.Cleanup(func() { getentPath = previous })

	_, err := lookupViaGetent("alice")
	if err == nil {
		t.Fatal("lookupViaGetent succeeded with no getent installed")
	}
	if !errors.Is(err, ErrUnknownAccount) {
		t.Errorf("error is %v, want one matching ErrUnknownAccount", err)
	}
	if !strings.Contains(err.Error(), "getent is unavailable") {
		t.Errorf("error %v does not say why the lookup could not be made", err)
	}
}
