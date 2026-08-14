package ipc

import (
	"strings"
	"testing"
)

func TestValidateUserID(t *testing.T) {
	tests := []struct {
		name    string
		userID  string
		wantErr bool
	}{
		{"valid simple", "testuser", false},
		{"valid with digits", "user123", false},
		{"valid with underscore", "_user", false},
		{"valid with hyphen", "test-user", false},
		{"valid samba account", "machine$", false},
		{"valid underscore start", "_test_user", false},
		{"valid single char", "a", false},
		{"empty", "", true},
		{"path traversal dots", "../../root", true},
		{"path traversal slash", "user/../../etc", true},
		{"starts with digit", "1user", true},
		{"starts with hyphen", "-user", true},
		{"uppercase", "TestUser", true},
		{"spaces", "test user", true},
		{"control chars", "user\x00name", true},
		{"too long", strings.Repeat("a", 33), true},
		{"max length", strings.Repeat("a", 32), false},
		{"dot in name", "user.name", true},
		{"at sign", "user@host", true},
		{"dollar not at end", "us$er", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUserID(tt.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUserID(%q) error = %v, wantErr %v", tt.userID, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSourceIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"empty allowed", "", false},
		{"valid IPv4", "192.168.1.100", false},
		{"valid IPv6", "::1", false},
		{"valid IPv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false},
		{"valid loopback", "127.0.0.1", false},
		{"invalid format", "not-an-ip", true},
		{"path traversal", "../../etc", true},
		{"too many octets", "1.2.3.4.5", true},
		{"out of range", "256.1.1.1", true},
		// (#169) A resolved hostname, which is what PAM_RHOST holds when sshd runs
		// with UseDNS on, is not a location the policy engine can evaluate. Clients
		// send it as metadata.rhost and leave source_ip out.
		{"hostname", "client.example.com", true},
		// An IPv6 zone is part of the literal the wire contract's 45 bytes allow for.
		{"IPv6 with zone", "fe80::1%eth0", false},
		{"longer than the contract allows", strings.Repeat("1", 46), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSourceIP(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSourceIP(%q) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSessionID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid alphanumeric", "abc123", false},
		{"valid with hyphens", "session-abc-123", false},
		{"valid with underscores", "session_abc_123", false},
		{"valid mixed", "Session-ID_123", false},
		{"empty", "", true},
		{"too long", strings.Repeat("a", 129), true},
		{"max length", strings.Repeat("a", 128), false},
		{"path traversal", "../../etc/passwd", true},
		{"spaces", "session id", true},
		{"control chars", "session\nid", true},
		{"special chars", "session;id", true},
		{"dots", "session.id", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSessionID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSessionID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestValidateStringField(t *testing.T) {
	tests := []struct {
		name    string
		val     string
		maxLen  int
		wantErr bool
	}{
		{"empty", "", 256, false},
		{"normal string", "hello world", 256, false},
		{"at max length", strings.Repeat("a", 256), 256, false},
		{"exceeds max length", strings.Repeat("a", 257), 256, true},
		{"control char null", "hello\x00world", 256, true},
		{"control char newline", "hello\nworld", 256, true},
		{"control char tab", "hello\tworld", 256, true},
		{"control char carriage return", "hello\rworld", 256, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStringField(tt.val, "test_field", tt.maxLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateStringField(%q) error = %v, wantErr %v", tt.val, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     Request
		wantErr bool
	}{
		{
			name: "valid authenticate",
			req: Request{
				Type:     "authenticate",
				UserID:   "testuser",
				SourceIP: "192.168.1.1",
			},
			wantErr: false,
		},
		{
			name: "authenticate missing user_id",
			req: Request{
				Type: "authenticate",
			},
			wantErr: true,
		},
		{
			name: "authenticate path traversal user_id",
			req: Request{
				Type:   "authenticate",
				UserID: "../../root",
			},
			wantErr: true,
		},
		{
			name: "authenticate invalid source_ip",
			req: Request{
				Type:     "authenticate",
				UserID:   "testuser",
				SourceIP: "not-an-ip",
			},
			wantErr: true,
		},
		{
			// (#169) target_host is a DNS name (this host), so the contract bounds it
			// at 253 rather than at maxFieldLen.
			name: "authenticate over-long target_host",
			req: Request{
				Type:       "authenticate",
				UserID:     "testuser",
				TargetHost: strings.Repeat("h", maxTargetHostLen+1),
			},
			wantErr: true,
		},
		{
			name: "authenticate control char in user_agent",
			req: Request{
				Type:      "authenticate",
				UserID:    "testuser",
				UserAgent: "agent\x00evil",
			},
			wantErr: true,
		},
		{
			name: "valid check_session",
			req: Request{
				Type:      "check_session",
				SessionID: "valid-session-123",
				UserID:    "testuser",
			},
			wantErr: false,
		},
		{
			name: "check_session missing user_id",
			req: Request{
				Type:      "check_session",
				SessionID: "valid-session-123",
			},
			wantErr: true,
		},
		{
			name: "check_session invalid user_id",
			req: Request{
				Type:      "check_session",
				SessionID: "valid-session-123",
				UserID:    "root; rm -rf /",
			},
			wantErr: true,
		},
		{
			name: "check_session missing session_id",
			req: Request{
				Type:   "check_session",
				UserID: "testuser",
			},
			wantErr: true,
		},
		{
			name: "valid refresh_session",
			req: Request{
				Type:      "refresh_session",
				SessionID: "valid-session-123",
				UserID:    "testuser",
			},
			wantErr: false,
		},
		{
			name: "refresh_session missing user_id",
			req: Request{
				Type:      "refresh_session",
				SessionID: "valid-session-123",
			},
			wantErr: true,
		},
		{
			name: "refresh_session invalid user_id",
			req: Request{
				Type:      "refresh_session",
				SessionID: "valid-session-123",
				UserID:    "root; rm -rf /",
			},
			wantErr: true,
		},
		{
			name: "refresh_session missing session_id",
			req: Request{
				Type:   "refresh_session",
				UserID: "testuser",
			},
			wantErr: true,
		},
		{
			name: "valid revoke_session",
			req: Request{
				Type:      "revoke_session",
				SessionID: "valid-session-123",
				UserID:    "testuser",
			},
			wantErr: false,
		},
		{
			name: "revoke_session missing user_id",
			req: Request{
				Type:      "revoke_session",
				SessionID: "valid-session-123",
			},
			wantErr: true,
		},
		{
			name: "revoke_session invalid user_id",
			req: Request{
				Type:      "revoke_session",
				SessionID: "valid-session-123",
				UserID:    "root; rm -rf /",
			},
			wantErr: true,
		},
		{
			name: "revoke_session missing session_id",
			req: Request{
				Type:   "revoke_session",
				UserID: "testuser",
			},
			wantErr: true,
		},
		{
			name: "unknown type passes validation",
			req: Request{
				Type: "unknown_type",
			},
			wantErr: false,
		},
		{
			name: "authenticate with optional session_id",
			req: Request{
				Type:      "authenticate",
				UserID:    "testuser",
				SessionID: "valid-session",
			},
			wantErr: false,
		},
		{
			name: "authenticate with invalid optional session_id",
			req: Request{
				Type:      "authenticate",
				UserID:    "testuser",
				SessionID: "invalid session!",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequest(&tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMetadata(t *testing.T) {
	tests := []struct {
		name    string
		meta    map[string]interface{}
		wantErr bool
	}{
		{"nil map", nil, false},
		{"empty map", map[string]interface{}{}, false},
		{"string value", map[string]interface{}{"k": "v"}, false},
		{"bool value", map[string]interface{}{"flag": true}, false},
		{"float64 value", map[string]interface{}{"score": float64(42)}, false},
		{"nil value", map[string]interface{}{"k": nil}, false},
		{"mixed valid types", map[string]interface{}{"a": "str", "b": true, "c": float64(1), "d": nil}, false},
		{
			"too many keys",
			func() map[string]interface{} {
				m := make(map[string]interface{})
				for i := 0; i < maxMetadataKeys+1; i++ {
					m[strings.Repeat("k", i+1)] = "v"
				}
				return m
			}(),
			true,
		},
		{"empty key", map[string]interface{}{"": "v"}, true},
		{"key too long", map[string]interface{}{strings.Repeat("k", maxMetadataKeyLen+1): "v"}, true},
		{"key with control char", map[string]interface{}{"key\x00bad": "v"}, true},
		{"string value too long", map[string]interface{}{"k": strings.Repeat("x", maxMetadataValueLen+1)}, true},
		{"string value with control char", map[string]interface{}{"k": "val\x00ue"}, true},
		{"unsupported type slice", map[string]interface{}{"k": []string{"a"}}, true},
		{"unsupported type map", map[string]interface{}{"k": map[string]string{"a": "b"}}, true},
		{"unsupported type int", map[string]interface{}{"k": 42}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMetadata(tt.meta)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRequestMetadata(t *testing.T) {
	// Verify metadata validation is wired into validateRequest for authenticate.
	tests := []struct {
		name    string
		meta    map[string]interface{}
		wantErr bool
	}{
		{"valid metadata", map[string]interface{}{"service": "sshd", "tty": "pts/0"}, false},
		{"unsupported value type", map[string]interface{}{"nested": map[string]interface{}{"a": "b"}}, true},
		{"value too long", map[string]interface{}{"k": strings.Repeat("x", maxMetadataValueLen+1)}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{
				Type:     "authenticate",
				UserID:   "testuser",
				Metadata: tt.meta,
			}
			err := validateRequest(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
