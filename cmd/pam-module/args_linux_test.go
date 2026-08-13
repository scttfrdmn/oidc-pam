//go:build linux

package main

import (
	"strings"
	"testing"
)

// defaultSocketPath is the compiled-in SOCKET_PATH. It must match the broker's
// own default for server.socket_path (pkg/config/config.go).
const defaultSocketPath = "/var/run/oidc-auth/broker.sock"

// defaultAuthTimeout is the compiled-in DEFAULT_AUTH_TIMEOUT, in seconds. It
// must stay below sshd's default LoginGraceTime of 120s.
const defaultAuthTimeout = 90

func TestParseModuleArgsDefaults(t *testing.T) {
	got := parseModuleArgs(nil)
	if got.socketPath != defaultSocketPath {
		t.Errorf("with no arguments: socket path = %q, want %q", got.socketPath, defaultSocketPath)
	}
	if got.timeoutSeconds != defaultAuthTimeout {
		t.Errorf("with no arguments: timeout = %ds, want %ds", got.timeoutSeconds, defaultAuthTimeout)
	}
	if got.timeoutSeconds >= 120 {
		t.Errorf("default timeout of %ds is not below sshd's default LoginGraceTime of 120s", got.timeoutSeconds)
	}
}

func TestParseModuleArgsTimeout(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"in-range value is accepted", []string{"timeout=300"}, 300},
		{"lower bound is accepted", []string{"timeout=10"}, 10},
		{"upper bound is accepted", []string{"timeout=900"}, 900},
		{"below the lower bound is rejected", []string{"timeout=1"}, defaultAuthTimeout},
		{"above the upper bound is rejected", []string{"timeout=901"}, defaultAuthTimeout},
		{"zero is rejected", []string{"timeout=0"}, defaultAuthTimeout},
		{"negative is rejected", []string{"timeout=-30"}, defaultAuthTimeout},
		{"non-numeric is rejected", []string{"timeout=soon"}, defaultAuthTimeout},
		{"trailing junk is rejected", []string{"timeout=30s"}, defaultAuthTimeout},
		{"empty value is rejected", []string{"timeout="}, defaultAuthTimeout},
		{"last override wins", []string{"timeout=30", "timeout=60"}, 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseModuleArgs(tt.args)
			if got.timeoutSeconds != tt.want {
				t.Errorf("parse_arguments(%q): timeout = %ds, want %ds", tt.args, got.timeoutSeconds, tt.want)
			}
			if got.socketPath != defaultSocketPath {
				t.Errorf("parse_arguments(%q): socket path = %q, want the default %q",
					tt.args, got.socketPath, defaultSocketPath)
			}
		})
	}
}

func TestParseModuleArgsSocketOverride(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "absolute path is accepted",
			args: []string{"socket=/run/oidc/test.sock"},
			want: "/run/oidc/test.sock",
		},
		{
			name: "override alongside other arguments",
			args: []string{"debug", "socket=/tmp/broker.sock"},
			want: "/tmp/broker.sock",
		},
		{
			name: "last override wins",
			args: []string{"socket=/tmp/first.sock", "socket=/tmp/second.sock"},
			want: "/tmp/second.sock",
		},
		{
			name: "relative path is rejected, default retained",
			args: []string{"socket=relative/broker.sock"},
			want: defaultSocketPath,
		},
		{
			name: "empty value is rejected, default retained",
			args: []string{"socket="},
			want: defaultSocketPath,
		},
		{
			name: "overlong path is rejected, default retained",
			args: []string{"socket=/" + strings.Repeat("x", 200)},
			want: defaultSocketPath,
		},
		{
			// The shipped su/sudo configs passed these; the module never
			// implemented any of them. They must not affect anything.
			name: "unknown arguments do not disturb the default",
			args: []string{"operation=sudo", "target_user=%u", "service=sshd"},
			want: defaultSocketPath,
		},
		{
			name: "config= is accepted but ignored",
			args: []string{"config=/etc/oidc-auth/broker.yaml"},
			want: defaultSocketPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseModuleArgs(tt.args).socketPath; got != tt.want {
				t.Errorf("parse_arguments(%q): socket path = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

// A path one byte too long for sun_path must be rejected rather than truncated:
// a truncated path names a different socket.
func TestParseModuleArgsSunPathLimit(t *testing.T) {
	atLimit := "/" + strings.Repeat("x", maxSocketPath-2) // maxSocketPath-1 bytes + NUL
	if got := parseModuleArgs([]string{"socket=" + atLimit}).socketPath; got != atLimit {
		t.Errorf("path of %d bytes should be accepted, got %q", len(atLimit), got)
	}

	tooLong := "/" + strings.Repeat("x", maxSocketPath-1) // maxSocketPath bytes + NUL
	if got := parseModuleArgs([]string{"socket=" + tooLong}).socketPath; got != defaultSocketPath {
		t.Errorf("path of %d bytes should be rejected, got %q", len(tooLong), got)
	}
}
