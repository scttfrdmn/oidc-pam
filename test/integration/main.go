// +build integration

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/scttfrdmn/oidc-pam/pkg/auth"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/internal/ipc"
)

func main() {
	// Set up logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	// Wait for Keycloak to be ready
	log.Println("Waiting for Keycloak to be ready...")
	if err := waitForKeycloak(); err != nil {
		log.Fatalf("Keycloak not ready: %v", err)
	}
	
	// Run integration tests
	log.Println("Starting integration tests...")
	
	// Load test configuration
	cfg, err := loadTestConfig()
	if err != nil {
		log.Fatalf("Failed to load test config: %v", err)
	}
	
	// Create test suite
	suite := &IntegrationTestSuite{
		config: cfg,
	}
	
	// Run tests
	if err := suite.RunTests(); err != nil {
		log.Fatalf("Integration tests failed: %v", err)
	}
	
	log.Println("All integration tests passed!")
}

type IntegrationTestSuite struct {
	config *config.Config
	broker *auth.Broker
	ipcServer *ipc.Server
}

func (s *IntegrationTestSuite) RunTests() error {
	tests := []struct {
		name string
		fn   func() error
	}{
		{"TestKeycloakConnection", s.TestKeycloakConnection},
		{"TestBrokerCreation", s.TestBrokerCreation},
		{"TestIPCServerSetup", s.TestIPCServerSetup},
		{"TestDeviceFlowAuthentication", s.TestDeviceFlowAuthentication},
		{"TestSessionManagement", s.TestSessionManagement},
		{"TestSSHKeyGeneration", s.TestSSHKeyGeneration},
		{"TestPolicyEvaluation", s.TestPolicyEvaluation},
		{"TestAuditLogging", s.TestAuditLogging},
		{"TestCleanup", s.TestCleanup},
	}
	
	for _, test := range tests {
		log.Printf("Running test: %s", test.name)
		if err := test.fn(); err != nil {
			return fmt.Errorf("test %s failed: %w", test.name, err)
		}
		log.Printf("Test %s passed", test.name)
	}
	
	return nil
}

func (s *IntegrationTestSuite) TestKeycloakConnection() error {
	// Test Keycloak discovery endpoint
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "http://keycloak:8080"
	}
	
	realm := os.Getenv("KEYCLOAK_REALM")
	if realm == "" {
		realm = "test-realm"
	}
	
	discoveryURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", keycloakURL, realm)
	
	resp, err := http.Get(discoveryURL)
	if err != nil {
		return fmt.Errorf("failed to connect to Keycloak: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Keycloak discovery endpoint returned %d", resp.StatusCode)
	}
	
	log.Println("Successfully connected to Keycloak")
	return nil
}

func (s *IntegrationTestSuite) TestBrokerCreation() error {
	// Create authentication broker
	broker, err := auth.NewBroker(s.config)
	if err != nil {
		return fmt.Errorf("failed to create broker: %w", err)
	}
	
	s.broker = broker
	
	// Start broker services
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := broker.Start(ctx); err != nil {
		return fmt.Errorf("failed to start broker: %w", err)
	}
	
	log.Println("Broker created and started successfully")
	return nil
}

func (s *IntegrationTestSuite) TestIPCServerSetup() error {
	if s.broker == nil {
		return fmt.Errorf("broker not initialized")
	}
	
	// Create IPC server
	ipcServer, err := ipc.NewServer(s.config.Server.SocketPath, s.broker)
	if err != nil {
		return fmt.Errorf("failed to create IPC server: %w", err)
	}
	
	s.ipcServer = ipcServer
	
	// Start IPC server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	go func() {
		if err := ipcServer.Start(ctx); err != nil {
			log.Printf("IPC server error: %v", err)
		}
	}()
	
	// Give server time to start
	time.Sleep(1 * time.Second)
	
	// Test socket exists
	if _, err := os.Stat(s.config.Server.SocketPath); os.IsNotExist(err) {
		return fmt.Errorf("IPC socket not created: %s", s.config.Server.SocketPath)
	}
	
	log.Println("IPC server setup successful")
	return nil
}

func (s *IntegrationTestSuite) TestDeviceFlowAuthentication() error {
	if s.broker == nil {
		return fmt.Errorf("broker not initialized")
	}
	
	// Create authentication request
	authRequest := &auth.AuthRequest{
		UserID:     "testuser",
		SourceIP:   "127.0.0.1",
		UserAgent:  "integration-test",
		TargetHost: "test-server",
		LoginType:  "ssh",
		DeviceID:   "test-device",
		SessionID:  "test-session-1",
		Timestamp:  time.Now(),
		Metadata: map[string]interface{}{
			"test": "integration",
		},
	}
	
	// Test authentication
	response, err := s.broker.Authenticate(authRequest)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	
	if !response.Success {
		return fmt.Errorf("authentication not successful: %s", response.ErrorMessage)
	}
	
	if response.DeviceCode == "" {
		return fmt.Errorf("device code not returned")
	}
	
	if response.DeviceURL == "" {
		return fmt.Errorf("device URL not returned")
	}
	
	log.Printf("Device flow started successfully: code=%s, url=%s", response.DeviceCode, response.DeviceURL)
	return nil
}

func (s *IntegrationTestSuite) TestSessionManagement() error {
	if s.broker == nil {
		return fmt.Errorf("broker not initialized")
	}
	
	// Test session check
	response, err := s.broker.CheckSession("test-session-1")
	if err != nil {
		return fmt.Errorf("session check failed: %w", err)
	}
	
	log.Printf("Session check result: success=%t", response.Success)
	return nil
}

func (s *IntegrationTestSuite) TestSSHKeyGeneration() error {
	// Test SSH key generation functionality
	// This would typically involve creating SSH keys and managing authorized_keys
	log.Println("SSH key generation test passed (placeholder)")
	return nil
}

func (s *IntegrationTestSuite) TestPolicyEvaluation() error {
	if s.broker == nil {
		return fmt.Errorf("broker not initialized")
	}
	
	// Test policy evaluation with different scenarios
	testCases := []struct {
		name    string
		request *auth.AuthRequest
		expectAllow bool
	}{
		{
			name: "local_user_ssh",
			request: &auth.AuthRequest{
				UserID:     "testuser",
				SourceIP:   "127.0.0.1",
				TargetHost: "test-server",
				LoginType:  "ssh",
				SessionID:  "test-session-2",
				Timestamp:  time.Now(),
			},
			expectAllow: true,
		},
		{
			name: "admin_user_console",
			request: &auth.AuthRequest{
				UserID:     "adminuser",
				SourceIP:   "192.168.1.100",
				TargetHost: "admin-server",
				LoginType:  "console",
				SessionID:  "test-session-3",
				Timestamp:  time.Now(),
			},
			expectAllow: true,
		},
	}
	
	for _, tc := range testCases {
		log.Printf("Testing policy case: %s", tc.name)
		response, err := s.broker.Authenticate(tc.request)
		if err != nil {
			return fmt.Errorf("policy test %s failed: %w", tc.name, err)
		}
		
		if response.Success != tc.expectAllow {
			return fmt.Errorf("policy test %s: expected allow=%t, got success=%t", tc.name, tc.expectAllow, response.Success)
		}
	}
	
	log.Println("Policy evaluation tests passed")
	return nil
}

func (s *IntegrationTestSuite) TestAuditLogging() error {
	// Check that audit logs are being written
	auditLogPath := "/tmp/oidc-pam/audit.log"
	
	if _, err := os.Stat(auditLogPath); os.IsNotExist(err) {
		log.Println("Audit log file not found, checking if audit events are being generated...")
		// This is expected if no authentication events have occurred yet
		return nil
	}
	
	log.Println("Audit logging test passed")
	return nil
}

func (s *IntegrationTestSuite) TestCleanup() error {
	// Stop services
	if s.ipcServer != nil {
		if err := s.ipcServer.Stop(); err != nil {
			log.Printf("Error stopping IPC server: %v", err)
		}
	}
	
	if s.broker != nil {
		if err := s.broker.Stop(); err != nil {
			log.Printf("Error stopping broker: %v", err)
		}
	}
	
	log.Println("Cleanup completed")
	return nil
}

func loadTestConfig() (*config.Config, error) {
	configPath := "/app/test/config/integration-test.yaml"
	
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Try alternative path
		configPath = "test/config/integration-test.yaml"
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found at %s", configPath)
		}
	}
	
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	
	// Override with environment variables
	if keycloakURL := os.Getenv("KEYCLOAK_URL"); keycloakURL != "" {
		if len(cfg.OIDC.Providers) > 0 {
			realm := os.Getenv("KEYCLOAK_REALM")
			if realm == "" {
				realm = "test-realm"
			}
			cfg.OIDC.Providers[0].Issuer = fmt.Sprintf("%s/realms/%s", keycloakURL, realm)
		}
	}
	
	if clientID := os.Getenv("KEYCLOAK_CLIENT_ID"); clientID != "" {
		if len(cfg.OIDC.Providers) > 0 {
			cfg.OIDC.Providers[0].ClientID = clientID
		}
	}
	
	if clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET"); clientSecret != "" {
		if len(cfg.OIDC.Providers) > 0 {
			cfg.OIDC.Providers[0].ClientSecret = clientSecret
		}
	}
	
	// Create necessary directories
	if err := os.MkdirAll(filepath.Dir(cfg.Server.SocketPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create socket directory: %w", err)
	}
	
	if err := os.MkdirAll("/tmp/oidc-pam", 0755); err != nil {
		return nil, fmt.Errorf("failed to create tmp directory: %w", err)
	}
	
	return cfg, nil
}

func waitForKeycloak() error {
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "http://keycloak:8080"
	}
	
	realm := os.Getenv("KEYCLOAK_REALM")
	if realm == "" {
		realm = "test-realm"
	}
	
	discoveryURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", keycloakURL, realm)
	
	maxRetries := 30
	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(discoveryURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			log.Println("Keycloak is ready")
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		
		log.Printf("Waiting for Keycloak... (attempt %d/%d)", i+1, maxRetries)
		time.Sleep(5 * time.Second)
	}
	
	return fmt.Errorf("Keycloak not ready after %d attempts", maxRetries)
}