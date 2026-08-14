package ipc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The socket's directory decides who can impersonate the broker.
//
// The socket file's own 0660 root mode is not the control that matters: write
// permission on the directory is enough to unlink(2) the socket and bind(2) an
// impostor at the same path, and no client verifies the server. The installers
// created the directory 0755 and chowned it to an unprivileged account that nothing
// runs as, so this was reachable from that uid alone (#200).
func TestSocketDirectoryOwnershipRule(t *testing.T) {
	const self = 1000

	cases := []struct {
		name       string
		owner      uint32
		mode       os.FileMode
		wantReject string // substring the refusal must explain; "" means accept
	}{
		{name: "root owned 0750, what the unit now creates", owner: 0, mode: 0750},
		{name: "root owned 0755", owner: 0, mode: 0755},
		{name: "owned by this process, as in $TMPDIR", owner: self, mode: 0700},
		{
			name:       "the installers' directory: 0755 owned by oidc-auth",
			owner:      999,
			mode:       0755,
			wantReject: "owned by uid 999",
		},
		{
			name:       "root owned but group writable",
			owner:      0,
			mode:       0770,
			wantReject: "group- or other-writable",
		},
		{
			name:       "root owned but world writable",
			owner:      0,
			mode:       0777,
			wantReject: "group- or other-writable",
		},
		{
			name:       "owned by a third account, not readable by others",
			owner:      42,
			mode:       0700,
			wantReject: "owned by uid 42",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSocketDirOwnership("/run/oidc-auth", tc.owner, tc.mode, self)
			switch {
			case tc.wantReject == "" && err != nil:
				t.Errorf("uid %d mode %04o was refused (%v), but no account other than "+
					"root or the broker itself can write to it", tc.owner, tc.mode, err)
			case tc.wantReject != "" && err == nil:
				t.Errorf("uid %d mode %04o was accepted, but that account can unlink the "+
					"broker's socket and bind an impostor in its place (#200)",
					tc.owner, tc.mode)
			case tc.wantReject != "" && !strings.Contains(err.Error(), tc.wantReject):
				t.Errorf("refusal for uid %d mode %04o was %q, which does not say %q, so an "+
					"operator cannot tell what to fix", tc.owner, tc.mode, err, tc.wantReject)
			}
		})
	}
}

// Start must apply the rule, not just define it. A directory this process created
// itself is accepted; the same directory made world-writable is not, and the broker
// refuses to serve rather than serving on a socket anyone can replace.
func TestStartRefusesAWorldWritableSocketDirectory(t *testing.T) {
	dir, err := os.MkdirTemp("", "ipcdir-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	socketPath := filepath.Join(dir, "broker.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Sanity: the directory as created is trusted, so the refusal below is caused by
	// the mode change and nothing else.
	server, err := NewServer(socketPath, nil, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start on a %s: %v", "0700 directory this process owns", err)
	}
	if err := server.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	server, err = NewServer(socketPath, nil, 0660, "", false, 0, 0)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	err = server.Start(ctx)
	if err == nil {
		_ = server.Stop()
		t.Fatal("Start succeeded with a world-writable socket directory: any local account " +
			"can now unlink the socket and bind an impostor that answers every login with " +
			"success (#200)")
	}
	for _, want := range []string{"refusing to listen", socketPath, "0777"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Start's refusal %q does not mention %q", err, want)
		}
	}

	// Fail closed: nothing may be listening on that path.
	if _, err := os.Stat(socketPath); err == nil {
		t.Error("Start refused but left a socket behind at the untrusted path")
	}
}
