package pam

import (
	"strings"
	"testing"
)

// defaultSocketPath is the compiled-in SOCKET_PATH. It must match the broker's
// own default for server.socket_path (pkg/config/config.go).
const defaultSocketPath = "/var/run/oidc-auth/broker.sock"

func TestParseModuleArgsDefaultSocketPath(t *testing.T) {
	if got := parseModuleArgs(nil); got != defaultSocketPath {
		t.Errorf("with no arguments: socket path = %q, want %q", got, defaultSocketPath)
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
			if got := parseModuleArgs(tt.args); got != tt.want {
				t.Errorf("parse_arguments(%q): socket path = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

// A path one byte too long for sun_path must be rejected rather than truncated:
// a truncated path names a different socket.
func TestParseModuleArgsSunPathLimit(t *testing.T) {
	atLimit := "/" + strings.Repeat("x", maxSocketPath-2) // maxSocketPath-1 bytes + NUL
	if got := parseModuleArgs([]string{"socket=" + atLimit}); got != atLimit {
		t.Errorf("path of %d bytes should be accepted, got %q", len(atLimit), got)
	}

	tooLong := "/" + strings.Repeat("x", maxSocketPath-1) // maxSocketPath bytes + NUL
	if got := parseModuleArgs([]string{"socket=" + tooLong}); got != defaultSocketPath {
		t.Errorf("path of %d bytes should be rejected, got %q", len(tooLong), got)
	}
}
