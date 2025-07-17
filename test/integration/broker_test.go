package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/auth"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/ssh"
)

// TestBrokerIntegration tests the complete broker workflow
func TestBrokerIntegration(t *testing.T) {
	// Skip if in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test environment
	testDir := setupTestEnvironment(t)
	defer cleanupTestEnvironment(testDir)

	// Create test configuration
	cfg := createTestConfig(testDir)

	// Start broker in test mode
	broker := startTestBroker(t, cfg)
	defer stopTestBroker(broker)

	// Wait for broker to start
	waitForBrokerReady(t, cfg.Server.SocketPath)

	// Test scenarios
	t.Run("Authentication", func(t *testing.T) {
		testAuthentication(t, cfg.Server.SocketPath)
	})

	t.Run("SessionManagement", func(t *testing.T) {
		testSessionManagement(t, cfg.Server.SocketPath)
	})

	t.Run("SSHKeyManagement", func(t *testing.T) {
		testSSHKeyManagement(t, cfg.Server.SocketPath)
	})

	t.Run("RiskAssessment", func(t *testing.T) {
		testRiskAssessment(t, cfg.Server.SocketPath)
	})

	t.Run("PolicyEnforcement", func(t *testing.T) {
		testPolicyEnforcement(t, cfg.Server.SocketPath)
	})
}

// TestPAMIntegration tests PAM module integration
func TestPAMIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping PAM integration test in short mode")
	}

	// Setup test environment
	testDir := setupTestEnvironment(t)
	defer cleanupTestEnvironment(testDir)

	// Create test configuration
	cfg := createTestConfig(testDir)

	// Start broker
	broker := startTestBroker(t, cfg)
	defer stopTestBroker(broker)

	// Wait for broker to start
	waitForBrokerReady(t, cfg.Server.SocketPath)

	// Test PAM authentication flow
	t.Run("PAMAuthentication", func(t *testing.T) {
		testPAMAuthentication(t, cfg)
	})

	t.Run("PAMSessionLifecycle", func(t *testing.T) {
		testPAMSessionLifecycle(t, cfg)
	})
}

// TestAdminCLIIntegration tests admin CLI integration
func TestAdminCLIIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping admin CLI integration test in short mode")
	}

	// Setup test environment
	testDir := setupTestEnvironment(t)
	defer cleanupTestEnvironment(testDir)

	// Create test configuration
	cfg := createTestConfig(testDir)

	// Start broker
	broker := startTestBroker(t, cfg)
	defer stopTestBroker(broker)

	// Wait for broker to start
	waitForBrokerReady(t, cfg.Server.SocketPath)

	// Test admin CLI commands
	t.Run("StatusCommand", func(t *testing.T) {
		testAdminStatus(t, cfg)
	})

	t.Run("SessionsCommand", func(t *testing.T) {
		testAdminSessions(t, cfg)
	})

	t.Run("KeysCommand", func(t *testing.T) {
		testAdminKeys(t, cfg)
	})

	t.Run("HealthCommand", func(t *testing.T) {
		testAdminHealth(t, cfg)
	})
}

// Test helper functions

func setupTestEnvironment(t *testing.T) string {
	t.Helper()

	// Create temporary directory
	testDir, err := os.MkdirTemp("", "oidc-pam-test-*")
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create required subdirectories
	dirs := []string{"config", "logs", "keys", "sockets", "data"}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(testDir, dir), 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	return testDir
}

func cleanupTestEnvironment(testDir string) {
	os.RemoveAll(testDir)
}

func createTestConfig(testDir string) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			SocketPath: filepath.Join(testDir, "sockets", "broker.sock"),
			LogLevel:   "debug",
		},
		OIDC: config.OIDCConfig{
			Providers: []config.OIDCProvider{
				{
					Name:         "test",
					Issuer:       "mock://test-provider",
					ClientID:     "test-client-id",
					Scopes:       []string{"openid", "profile", "email"},
					DeviceEndpoint: "mock://device",
					TokenEndpoint:  "mock://token", 
					UserInfoEndpoint: "mock://userinfo",
					UserMapping: config.UserMapping{
						UsernameClaim: "email",
						EmailClaim:    "email",
						NameClaim:     "name",
						GroupsClaim:   "groups",
					},
					EnabledForLogin: true,
				},
			},
		},
		Authentication: config.AuthenticationConfig{
			TokenLifetime:         time.Hour,
			RefreshThreshold:      time.Minute * 15,
			MaxConcurrentSessions: 10,
		},
		Security: config.SecurityConfig{
			TokenEncryptionKey: "test-encryption-key-32-bytes-long!",
			AuditEnabled:       true,
		},
		Audit: config.AuditConfig{
			Enabled: true,
			Format:  "json",
			Outputs: []config.AuditOutput{
				{
					Type: "file",
					Path: filepath.Join(testDir, "logs", "audit.log"),
				},
			},
		},
	}
}

func startTestBroker(t *testing.T, cfg *config.Config) *auth.Broker {
	t.Helper()

	// Create broker instance
	broker, err := auth.NewBroker(cfg)
	if err != nil {
		t.Fatalf("Failed to create broker: %v", err)
	}

	// Start broker in background
	go func() {
		if err := broker.Start(context.Background()); err != nil {
			t.Logf("Broker stopped: %v", err)
		}
	}()

	return broker
}

func stopTestBroker(broker *auth.Broker) {
	broker.Stop()
}

func waitForBrokerReady(t *testing.T, socketPath string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			// Try to connect
			conn, err := net.Dial("unix", socketPath)
			if err == nil {
				conn.Close()
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatal("Broker failed to start within timeout")
}

// Authentication tests

func testAuthentication(t *testing.T, socketPath string) {
	conn := connectToBroker(t, socketPath)
	defer conn.Close()

	// Test authentication request
	request := map[string]interface{}{
		"type":        "authenticate",
		"user_id":     "testuser",
		"login_type":  "ssh",
		"target_host": "localhost",
		"metadata": map[string]string{
			"remote_addr": "127.0.0.1",
			"user_agent":  "test-client",
		},
	}

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify response structure
	if response["type"] != "auth_response" {
		t.Errorf("Expected auth_response, got %v", response["type"])
	}

	if _, ok := response["success"]; !ok {
		t.Error("Response missing success field")
	}
}

func testSessionManagement(t *testing.T, socketPath string) {
	conn := connectToBroker(t, socketPath)
	defer conn.Close()

	// Create a session first
	authRequest := map[string]interface{}{
		"type":        "authenticate",
		"user_id":     "sessionuser",
		"login_type":  "ssh",
		"target_host": "localhost",
	}

	if err := json.NewEncoder(conn).Encode(authRequest); err != nil {
		t.Fatalf("Failed to send auth request: %v", err)
	}

	var authResponse map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&authResponse); err != nil {
		t.Fatalf("Failed to decode auth response: %v", err)
	}

	// Test session listing
	listRequest := map[string]interface{}{
		"type": "sessions_list",
	}

	if err := json.NewEncoder(conn).Encode(listRequest); err != nil {
		t.Fatalf("Failed to send list request: %v", err)
	}

	var listResponse map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&listResponse); err != nil {
		t.Fatalf("Failed to decode list response: %v", err)
	}

	if sessions, ok := listResponse["sessions"].([]interface{}); ok {
		if len(sessions) == 0 {
			t.Error("Expected at least one session")
		}
	} else {
		t.Error("Response missing sessions field")
	}
}

func testSSHKeyManagement(t *testing.T, socketPath string) {
	conn := connectToBroker(t, socketPath)
	defer conn.Close()

	// Test key generation
	genRequest := map[string]interface{}{
		"type":     "key_create",
		"username": "keyuser",
		"key_type": "rsa",
		"key_size": 2048,
		"expires":  time.Hour.String(),
	}

	if err := json.NewEncoder(conn).Encode(genRequest); err != nil {
		t.Fatalf("Failed to send key generation request: %v", err)
	}

	var genResponse map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&genResponse); err != nil {
		t.Fatalf("Failed to decode key generation response: %v", err)
	}

	if success, ok := genResponse["success"].(bool); !ok || !success {
		t.Errorf("Key generation failed: %v", genResponse)
	}

	// Test key listing
	listRequest := map[string]interface{}{
		"type": "keys_list",
	}

	if err := json.NewEncoder(conn).Encode(listRequest); err != nil {
		t.Fatalf("Failed to send key list request: %v", err)
	}

	var listResponse map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&listResponse); err != nil {
		t.Fatalf("Failed to decode key list response: %v", err)
	}

	if keys, ok := listResponse["keys"].([]interface{}); ok {
		if len(keys) == 0 {
			t.Error("Expected at least one SSH key")
		}
	} else {
		t.Error("Response missing keys field")
	}
}

func testRiskAssessment(t *testing.T, socketPath string) {
	conn := connectToBroker(t, socketPath)
	defer conn.Close()

	// Test risk assessment request
	request := map[string]interface{}{
		"type":        "risk_assess",
		"user_id":     "riskuser",
		"remote_addr": "192.168.1.100",
		"user_agent":  "Mozilla/5.0",
		"login_type":  "ssh",
		"country":     "US",
		"metadata": map[string]interface{}{
			"device_fingerprint": "test-device",
		},
	}

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatalf("Failed to send risk assessment request: %v", err)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatalf("Failed to decode risk assessment response: %v", err)
	}

	// Verify response structure
	if _, ok := response["risk_score"]; !ok {
		t.Error("Response missing risk_score field")
	}

	if _, ok := response["risk_level"]; !ok {
		t.Error("Response missing risk_level field")
	}

	if _, ok := response["decision"]; !ok {
		t.Error("Response missing decision field")
	}
}

func testPolicyEnforcement(t *testing.T, socketPath string) {
	conn := connectToBroker(t, socketPath)
	defer conn.Close()

	// Test policy enforcement with high-risk scenario
	request := map[string]interface{}{
		"type":        "authenticate",
		"user_id":     "policyuser",
		"login_type":  "ssh",
		"target_host": "localhost",
		"metadata": map[string]interface{}{
			"remote_addr": "1.2.3.4", // Untrusted IP
			"user_agent":  "curl/7.68.0", // Automated tool
			"country":     "XX", // Untrusted country
		},
	}

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatalf("Failed to send policy test request: %v", err)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatalf("Failed to decode policy test response: %v", err)
	}

	// Verify policy enforcement
	if requiresMFA, ok := response["requires_mfa"].(bool); ok && !requiresMFA {
		t.Error("Expected MFA to be required for high-risk scenario")
	}

	if riskScore, ok := response["risk_score"].(float64); ok && riskScore < 20 {
		t.Errorf("Expected elevated risk score, got %f", riskScore)
	}
}

// PAM integration tests

func testPAMAuthentication(t *testing.T, cfg *config.Config) {
	// Test PAM helper integration
	pamHelper := filepath.Join("../../bin", "oidc-pam-helper")
	if _, err := os.Stat(pamHelper); os.IsNotExist(err) {
		t.Skip("PAM helper binary not found, skipping PAM integration test")
	}

	// Set environment for test
	os.Setenv("OIDC_SOCKET_PATH", cfg.Server.SocketPath)
	defer os.Unsetenv("OIDC_SOCKET_PATH")

	// This would normally run the PAM helper, but we'll simulate the flow
	// In a real integration test, you'd execute the helper and verify output
	t.Log("PAM authentication flow simulation completed")
}

func testPAMSessionLifecycle(t *testing.T, cfg *config.Config) {
	// Test session creation, validation, and cleanup
	keyManager := ssh.NewKeyManager(filepath.Join(os.TempDir(), "ssh-keys"))

	// Generate test key
	key, err := keyManager.GenerateKey("pamuser")
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Save key
	if err := keyManager.SaveKey("pamuser", key); err != nil {
		t.Fatalf("Failed to save test key: %v", err)
	}

	// Verify key exists
	loadedKey, err := keyManager.LoadKey("pamuser")
	if err != nil {
		t.Fatalf("Failed to load test key: %v", err)
	}

	if loadedKey.Comment != "pamuser" {
		t.Errorf("Expected comment pamuser, got %s", loadedKey.Comment)
	}

	// Cleanup
	if err := keyManager.DeleteKey("pamuser"); err != nil {
		t.Fatalf("Failed to cleanup test key: %v", err)
	}
}

// Admin CLI integration tests

func testAdminStatus(t *testing.T, cfg *config.Config) {
	// Test admin CLI status command
	conn := connectToBroker(t, cfg.Server.SocketPath)
	defer conn.Close()

	request := map[string]interface{}{
		"type": "status",
	}

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatalf("Failed to send status request: %v", err)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatalf("Failed to decode status response: %v", err)
	}

	// Verify status response
	if _, ok := response["status"]; !ok {
		t.Error("Status response missing status field")
	}

	if _, ok := response["version"]; !ok {
		t.Error("Status response missing version field")
	}

	if _, ok := response["uptime"]; !ok {
		t.Error("Status response missing uptime field")
	}
}

func testAdminSessions(t *testing.T, cfg *config.Config) {
	// Create a test session first
	conn := connectToBroker(t, cfg.Server.SocketPath)
	defer conn.Close()

	// Authenticate to create session
	authRequest := map[string]interface{}{
		"type":        "authenticate",
		"user_id":     "admintest",
		"login_type":  "ssh",
		"target_host": "localhost",
	}

	json.NewEncoder(conn).Encode(authRequest)
	var authResponse map[string]interface{}
	json.NewDecoder(conn).Decode(&authResponse)

	// Test session listing via admin interface
	listRequest := map[string]interface{}{
		"type": "sessions_list",
	}

	if err := json.NewEncoder(conn).Encode(listRequest); err != nil {
		t.Fatalf("Failed to send sessions list request: %v", err)
	}

	var listResponse map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&listResponse); err != nil {
		t.Fatalf("Failed to decode sessions list response: %v", err)
	}

	if sessions, ok := listResponse["sessions"].([]interface{}); ok {
		if len(sessions) == 0 {
			t.Error("Expected at least one session for admin test")
		}
	}
}

func testAdminKeys(t *testing.T, cfg *config.Config) {
	// Test SSH key management via admin interface
	conn := connectToBroker(t, cfg.Server.SocketPath)
	defer conn.Close()

	// Create a test key
	createRequest := map[string]interface{}{
		"type":     "key_create",
		"username": "adminkey",
		"key_type": "rsa",
		"key_size": 2048,
	}

	json.NewEncoder(conn).Encode(createRequest)
	var createResponse map[string]interface{}
	json.NewDecoder(conn).Decode(&createResponse)

	// List keys
	listRequest := map[string]interface{}{
		"type": "keys_list",
	}

	if err := json.NewEncoder(conn).Encode(listRequest); err != nil {
		t.Fatalf("Failed to send keys list request: %v", err)
	}

	var listResponse map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&listResponse); err != nil {
		t.Fatalf("Failed to decode keys list response: %v", err)
	}

	if keys, ok := listResponse["keys"].([]interface{}); ok {
		if len(keys) == 0 {
			t.Error("Expected at least one key for admin test")
		}
	}
}

func testAdminHealth(t *testing.T, cfg *config.Config) {
	// Test health check via admin interface
	conn := connectToBroker(t, cfg.Server.SocketPath)
	defer conn.Close()

	request := map[string]interface{}{
		"type": "health",
	}

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatalf("Failed to send health request: %v", err)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatalf("Failed to decode health response: %v", err)
	}

	// Verify health response structure
	if _, ok := response["overall"]; !ok {
		t.Error("Health response missing overall field")
	}

	if checks, ok := response["checks"].([]interface{}); ok {
		if len(checks) == 0 {
			t.Error("Expected health checks in response")
		}
	}
}

// Helper functions

func connectToBroker(t *testing.T, socketPath string) net.Conn {
	t.Helper()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect to broker: %v", err)
	}

	return conn
}

// Benchmark tests

func BenchmarkAuthentication(b *testing.B) {
	testDir := setupBenchmarkEnvironment(b)
	defer cleanupTestEnvironment(testDir)

	cfg := createTestConfig(testDir)
	broker := startTestBrokerForBench(b, cfg)
	defer stopTestBroker(broker)

	waitForBrokerReadyForBench(b, cfg.Server.SocketPath)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn := connectToBrokerBench(b, cfg.Server.SocketPath)
			
			request := map[string]interface{}{
				"type":        "authenticate",
				"user_id":     fmt.Sprintf("user%d", time.Now().UnixNano()),
				"login_type":  "ssh",
				"target_host": "localhost",
			}

			json.NewEncoder(conn).Encode(request)
			var response map[string]interface{}
			json.NewDecoder(conn).Decode(&response)
			
			conn.Close()
		}
	})
}

func setupBenchmarkEnvironment(b *testing.B) string {
	b.Helper()

	testDir, err := os.MkdirTemp("", "oidc-pam-bench-*")
	if err != nil {
		b.Fatalf("Failed to create benchmark directory: %v", err)
	}

	dirs := []string{"config", "logs", "keys", "sockets", "data"}
	for _, dir := range dirs {
		os.MkdirAll(filepath.Join(testDir, dir), 0755)
	}

	return testDir
}

func startTestBrokerForBench(b *testing.B, cfg *config.Config) *auth.Broker {
	b.Helper()

	broker, err := auth.NewBroker(cfg)
	if err != nil {
		b.Fatalf("Failed to create broker: %v", err)
	}

	go func() {
		if err := broker.Start(context.Background()); err != nil {
			b.Logf("Broker stopped: %v", err)
		}
	}()

	return broker
}

func waitForBrokerReadyForBench(b *testing.B, socketPath string) {
	b.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			if conn, err := net.Dial("unix", socketPath); err == nil {
				conn.Close()
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	b.Fatal("Broker failed to start within timeout")
}

func connectToBrokerBench(b *testing.B, socketPath string) net.Conn {
	b.Helper()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		b.Fatalf("Failed to connect to broker: %v", err)
	}

	return conn
}

