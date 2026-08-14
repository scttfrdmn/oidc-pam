package security

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/oidc-pam/pkg/config"
)

// fileAuditConfig is an audit configuration whose only output is a file in dir,
// with the default overflow strategy ("" → block), which is what a broker runs
// with unless an operator opts into dropping records.
func fileAuditConfig(path string) config.AuditConfig {
	return config.AuditConfig{
		Enabled: true,
		Format:  "json",
		Outputs: []config.AuditOutput{{Type: "file", Path: path}},
	}
}

// nonCriticalEvent is an event LogAuthEvent routes through the async channel
// rather than writing synchronously — see isCriticalEvent. The distinction is
// the whole point of the test below: critical events were never at risk, and
// everything else was.
func nonCriticalEvent(user string) AuditEvent {
	return AuditEvent{EventType: "data_access", UserID: user, Success: true}
}

// TestStopWritesEventsStillQueued pins the behaviour that Stop means "the
// accepted events have been written".
//
// The logger is deliberately never started, which puts three events in the
// buffer with no worker to consume them — the same state a broker is in when it
// shuts down while the worker is between iterations, made deterministic. Before
// the fix, processEvents returned on stopChan without looking at the buffer and
// Stop discarded all three, so this test found an empty file.
func TestStopWritesEventsStillQueued(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "queued.log")

	logger, err := NewAuditLogger(fileAuditConfig(logFile))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	for _, user := range []string{"alice", "bob", "carol"} {
		logger.LogAuthEvent(nonCriticalEvent(user))
	}

	if err := logger.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read %s: %v", logFile, err)
	}
	for _, user := range []string{"alice", "bob", "carol"} {
		if !strings.Contains(string(data), user) {
			t.Errorf("Stop lost the queued event for %q; audit log holds %d bytes", user, len(data))
		}
	}
}

// TestStopDrainsAfterTheContextIsCancelled covers the other way the worker
// leaves: a cancelled context. The broker's audit logger is started with the
// server's context, so this is what shutdown actually looks like, and events
// logged in the window between cancellation and Stop must still be written.
func TestStopDrainsAfterTheContextIsCancelled(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "cancelled.log")

	logger, err := NewAuditLogger(fileAuditConfig(logFile))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := logger.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	cancel()

	logger.LogAuthEvent(nonCriticalEvent("dave"))

	if err := logger.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read %s: %v", logFile, err)
	}
	if !strings.Contains(string(data), "dave") {
		t.Errorf("event logged after cancellation was not written; audit log holds %d bytes", len(data))
	}
}

// TestStopIsIdempotent exists because Stop closes a channel, and the tests and
// shutdown paths that both stop the logger — one directly, one in a defer — are
// the normal shape rather than a bug. A second Stop used to panic.
func TestStopIsIdempotent(t *testing.T) {
	logger, err := NewAuditLogger(fileAuditConfig(filepath.Join(t.TempDir(), "twice.log")))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := logger.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := logger.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := logger.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}
