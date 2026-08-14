package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The PAM stacks in configs/pam must not pass `debug`.
//
// `debug` makes the module log the details of every authentication that service
// handles to LOG_AUTHPRIV — before #168, that included the broker's entire
// response, device code and instructions and all. The shipped ssh and login stacks
// passed it, so every host built by copying them into /etc/pam.d logged that on
// every login; the ssh config even carried a note telling the reader to take it
// out again. It is a diagnostic an operator turns on while watching a login, not a
// default.
//
// This test has no build tag on purpose: it reads files, needs no cgo, and the
// stacks are worth pinning on a developer's Mac too.
func TestShippedPAMStacksDoNotEnableDebug(t *testing.T) {
	dir := filepath.Join("..", "..", "configs", "pam")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	moduleLines := 0
	for _, entry := range entries {
		// README.md documents the `debug` argument deliberately; it is not a stack.
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".md") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}

		for i, line := range strings.Split(string(content), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			if !strings.Contains(line, "pam_oidc.so") {
				continue
			}
			moduleLines++

			for _, field := range fields {
				if field == "debug" {
					t.Errorf("%s:%d ships `debug`, so every login this stack handles logs its "+
						"details to LOG_AUTHPRIV: %s", path, i+1, strings.TrimSpace(line))
				}
			}
		}
	}

	if moduleLines == 0 {
		t.Fatalf("found no pam_oidc.so lines under %s; this test is checking nothing", dir)
	}
}
