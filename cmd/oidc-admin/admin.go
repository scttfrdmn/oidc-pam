package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/rs/zerolog/log"
)

// Types for communication with broker
type StatusResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
	Timestamp time.Time `json:"timestamp"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Provider  string    `json:"provider"`
	LoginType string    `json:"login_type"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

type SessionListResponse struct {
	Sessions []Session `json:"sessions"`
	Total    int       `json:"total"`
}

type SSHKeyInfo struct {
	Username  string    `json:"username"`
	KeyType   string    `json:"key_type"`
	KeySize   int       `json:"key_size"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type KeyListResponse struct {
	Keys  []SSHKeyInfo `json:"keys"`
	Total int          `json:"total"`
}

// Simple admin commands without initialization cycles

var adminStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show system status",
	Long:  `Display the current status of the OIDC PAM authentication system.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := showSystemStatus(); err != nil {
			log.Error().Err(err).Msg("Failed to get status")
			os.Exit(1)
		}
	},
}

var adminHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Show system health",
	Long:  `Display detailed health information for the OIDC PAM system.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := showSystemHealth(); err != nil {
			log.Error().Err(err).Msg("Failed to get health status")
			os.Exit(1)
		}
	},
}

var adminSessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "List active sessions",
	Long:  `Display all active user sessions.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := listActiveSessions(); err != nil {
			log.Error().Err(err).Msg("Failed to list sessions")
			os.Exit(1)
		}
	},
}

var adminKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "List SSH keys",
	Long:  `Display all SSH keys managed by the system.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := listSSHKeys(); err != nil {
			log.Error().Err(err).Msg("Failed to list keys")
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(adminStatusCmd)
	rootCmd.AddCommand(adminHealthCmd)
	rootCmd.AddCommand(adminSessionsCmd)
	rootCmd.AddCommand(adminKeysCmd)
}

// System status
func showSystemStatus() error {
	socketPath := "/var/run/oidc-auth/broker.sock"
	if path := os.Getenv("OIDC_SOCKET_PATH"); path != "" {
		socketPath = path
	}

	// Check if broker is running
	if !isServiceRunning(socketPath) {
		fmt.Printf("🔴 OIDC PAM Status: STOPPED\n")
		fmt.Printf("==================\n\n")
		fmt.Printf("The OIDC authentication broker is not running.\n")
		fmt.Printf("Socket path: %s\n", socketPath)
		return nil
	}

	// Get status from broker
	status, err := getBrokerStatusSimple(socketPath)
	if err != nil {
		return fmt.Errorf("failed to get broker status: %w", err)
	}

	fmt.Printf("🟢 OIDC PAM Status: RUNNING\n")
	fmt.Printf("===========================\n\n")
	fmt.Printf("Version:    %s\n", status.Version)
	fmt.Printf("Uptime:     %s\n", status.Uptime)
	fmt.Printf("Status:     %s\n", status.Status)
	fmt.Printf("Socket:     %s\n", socketPath)

	return nil
}

// System health
func showSystemHealth() error {
	socketPath := "/var/run/oidc-auth/broker.sock"
	if path := os.Getenv("OIDC_SOCKET_PATH"); path != "" {
		socketPath = path
	}

	fmt.Printf("🏥 OIDC PAM Health Check\n")
	fmt.Printf("========================\n\n")

	// Check broker service
	if isServiceRunning(socketPath) {
		fmt.Printf("✅ Broker Service: Running\n")
	} else {
		fmt.Printf("❌ Broker Service: Not running\n")
		return nil
	}

	// Check socket permissions
	if info, err := os.Stat(socketPath); err == nil {
		fmt.Printf("✅ Socket Permissions: %s\n", info.Mode())
	} else {
		fmt.Printf("❌ Socket Permissions: Cannot access\n")
	}

	// Check configuration file
	configPaths := []string{
		"/etc/oidc-auth/broker.yaml",
		"/etc/oidc-auth/broker.yml",
		"broker.yaml",
		"broker.yml",
	}

	configFound := false
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("✅ Configuration: Found at %s\n", path)
			configFound = true
			break
		}
	}

	if !configFound {
		fmt.Printf("⚠️  Configuration: Not found in standard locations\n")
	}

	return nil
}

// List active sessions
func listActiveSessions() error {
	socketPath := "/var/run/oidc-auth/broker.sock"
	if path := os.Getenv("OIDC_SOCKET_PATH"); path != "" {
		socketPath = path
	}

	if !isServiceRunning(socketPath) {
		return fmt.Errorf("broker service is not running")
	}

	sessions, err := getSessionsSimple(socketPath)
	if err != nil {
		return fmt.Errorf("failed to get sessions: %w", err)
	}

	fmt.Printf("📊 Active Sessions\n")
	fmt.Printf("==================\n\n")

	if len(sessions) == 0 {
		fmt.Printf("No active sessions.\n")
		return nil
	}

	fmt.Printf("Total sessions: %d\n\n", len(sessions))
	fmt.Printf("%-20s %-15s %-10s %-20s\n", "User", "Provider", "Type", "Created")
	fmt.Printf("%-20s %-15s %-10s %-20s\n", 
		strings.Repeat("-", 20), 
		strings.Repeat("-", 15), 
		strings.Repeat("-", 10), 
		strings.Repeat("-", 20))

	for _, session := range sessions {
		fmt.Printf("%-20s %-15s %-10s %-20s\n", 
			truncateString(session.UserID, 20),
			truncateString(session.Provider, 15),
			truncateString(session.LoginType, 10),
			session.CreatedAt.Format("2006-01-02 15:04:05"))
	}

	return nil
}

// List SSH keys
func listSSHKeys() error {
	socketPath := "/var/run/oidc-auth/broker.sock"
	if path := os.Getenv("OIDC_SOCKET_PATH"); path != "" {
		socketPath = path
	}

	if !isServiceRunning(socketPath) {
		return fmt.Errorf("broker service is not running")
	}

	keys, err := getKeysSimple(socketPath)
	if err != nil {
		return fmt.Errorf("failed to get SSH keys: %w", err)
	}

	fmt.Printf("🔑 SSH Keys\n")
	fmt.Printf("===========\n\n")

	if len(keys) == 0 {
		fmt.Printf("No SSH keys found.\n")
		return nil
	}

	fmt.Printf("Total keys: %d\n\n", len(keys))
	fmt.Printf("%-20s %-10s %-8s %-8s %-20s\n", "Username", "Type", "Size", "Status", "Created")
	fmt.Printf("%-20s %-10s %-8s %-8s %-20s\n", 
		strings.Repeat("-", 20), 
		strings.Repeat("-", 10), 
		strings.Repeat("-", 8), 
		strings.Repeat("-", 8), 
		strings.Repeat("-", 20))

	for _, key := range keys {
		fmt.Printf("%-20s %-10s %-8d %-8s %-20s\n", 
			truncateString(key.Username, 20),
			truncateString(key.KeyType, 10),
			key.KeySize,
			truncateString(key.Status, 8),
			key.CreatedAt.Format("2006-01-02 15:04:05"))
	}

	return nil
}

// Helper functions
func isServiceRunning(socketPath string) bool {
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return false
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func getBrokerStatusSimple(socketPath string) (*StatusResponse, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to broker: %w", err)
	}
	defer func() { _ = conn.Close() }()

	request := map[string]interface{}{
		"type": "status",
	}

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	var response StatusResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

func getSessionsSimple(socketPath string) ([]Session, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to broker: %w", err)
	}
	defer func() { _ = conn.Close() }()

	request := map[string]interface{}{
		"type": "sessions_list",
	}

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	var response SessionListResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Sessions, nil
}

func getKeysSimple(socketPath string) ([]SSHKeyInfo, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to broker: %w", err)
	}
	defer func() { _ = conn.Close() }()

	request := map[string]interface{}{
		"type": "keys_list",
	}

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	var response KeyListResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Keys, nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}