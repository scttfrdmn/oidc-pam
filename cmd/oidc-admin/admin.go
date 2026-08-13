package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/internal/adminapi"
	"github.com/scttfrdmn/oidc-pam/pkg/security"
	"github.com/spf13/cobra"
)

// The request/response types live in internal/adminapi so that this client and
// the broker's IPC server share one definition. They used to be declared here
// and again on the server side, and the two had drifted: the types this file
// sends were not implemented by the broker at all.

// defaultSocketPath matches the broker's server.socket_path default; override it
// with OIDC_SOCKET_PATH.
const defaultSocketPath = "/var/run/oidc-auth/broker.sock"

// requestTimeout bounds a single admin request end to end. Without it a broker
// that accepts the connection and then stops responding would hang the CLI
// indefinitely.
const requestTimeout = 10 * time.Second

func socketPath() string {
	if path := os.Getenv("OIDC_SOCKET_PATH"); path != "" {
		return path
	}
	return defaultSocketPath
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

var adminGenKeyCmd = &cobra.Command{
	Use:   "gen-key",
	Short: "Generate a token encryption key",
	Long: `Generate a new base64-encoded 32-byte (AES-256) key suitable for
security.token_encryption_key in broker.yaml. The output is the value to set;
keep it secret and supply it via the config file or an env:/file: reference.`,
	Run: func(cmd *cobra.Command, args []string) {
		key, err := security.GenerateKey()
		if err != nil {
			log.Error().Err(err).Msg("Failed to generate key")
			os.Exit(1)
		}
		fmt.Println(key)
	},
}

func init() {
	rootCmd.AddCommand(adminStatusCmd)
	rootCmd.AddCommand(adminHealthCmd)
	rootCmd.AddCommand(adminSessionsCmd)
	rootCmd.AddCommand(adminKeysCmd)
	rootCmd.AddCommand(adminGenKeyCmd)
}

// System status
func showSystemStatus() error {
	status, err := getBrokerStatus()
	if errors.Is(err, errBrokerUnreachable) {
		fmt.Printf("🔴 OIDC PAM Status: STOPPED\n")
		fmt.Printf("==================\n\n")
		fmt.Printf("The OIDC authentication broker is not reachable.\n")
		fmt.Printf("Socket path: %s\n", socketPath())
		fmt.Printf("Reason:      %v\n", errors.Unwrap(err))
		return nil
	}
	if err != nil {
		return err
	}

	fmt.Printf("🟢 OIDC PAM Status: RUNNING\n")
	fmt.Printf("===========================\n\n")
	fmt.Printf("Version:    %s\n", status.Version)
	fmt.Printf("Uptime:     %s\n", status.Uptime)
	fmt.Printf("Started:    %s\n", status.StartedAt.Format(time.RFC3339))
	fmt.Printf("Status:     %s\n", status.Status)
	fmt.Printf("Sessions:   %d active, %d pending\n", status.ActiveSessions, status.PendingSessions)
	fmt.Printf("Providers:  %s\n", strings.Join(status.Providers, ", "))
	fmt.Printf("Socket:     %s\n", socketPath())

	return nil
}

// System health
func showSystemHealth() error {
	path := socketPath()

	fmt.Printf("🏥 OIDC PAM Health Check\n")
	fmt.Printf("========================\n\n")

	// Check broker service. This is a real request rather than a bare connect:
	// a broker that accepts connections but cannot answer them is not healthy,
	// and a connect-and-drop looks identical to a working request from outside.
	status, err := getBrokerStatus()
	switch {
	case errors.Is(err, errBrokerUnreachable):
		fmt.Printf("❌ Broker Service: Not reachable (%v)\n", errors.Unwrap(err))
		return nil
	case err != nil:
		fmt.Printf("❌ Broker Service: Reachable but not answering (%v)\n", err)
		return nil
	default:
		fmt.Printf("✅ Broker Service: Running (version %s, up %s)\n", status.Version, status.Uptime)
	}

	// Check socket permissions
	if info, err := os.Stat(path); err == nil {
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

	if len(status.Providers) > 0 {
		fmt.Printf("✅ Providers: %s\n", strings.Join(status.Providers, ", "))
	} else {
		fmt.Printf("⚠️  Providers: None configured\n")
	}

	return nil
}

// List active sessions
func listActiveSessions() error {
	var response adminapi.SessionListResponse
	if err := adminRequest("sessions_list", &response); err != nil {
		return err
	}

	fmt.Printf("📊 Sessions\n")
	fmt.Printf("===========\n\n")

	if len(response.Sessions) == 0 {
		fmt.Printf("No sessions.\n")
		return nil
	}

	fmt.Printf("Total sessions: %d\n\n", response.Total)
	fmt.Printf("%-20s %-15s %-10s %-9s %-20s\n", "User", "Provider", "Type", "Status", "Created")
	fmt.Printf("%-20s %-15s %-10s %-9s %-20s\n",
		strings.Repeat("-", 20),
		strings.Repeat("-", 15),
		strings.Repeat("-", 10),
		strings.Repeat("-", 9),
		strings.Repeat("-", 20))

	for _, session := range response.Sessions {
		fmt.Printf("%-20s %-15s %-10s %-9s %-20s\n",
			truncateString(session.UserID, 20),
			truncateString(session.Provider, 15),
			truncateString(session.LoginType, 10),
			truncateString(session.Status, 9),
			session.CreatedAt.Format("2006-01-02 15:04:05"))
	}

	return nil
}

// List SSH keys
func listSSHKeys() error {
	var response adminapi.KeyListResponse
	if err := adminRequest("keys_list", &response); err != nil {
		return err
	}

	fmt.Printf("🔑 SSH Keys\n")
	fmt.Printf("===========\n\n")

	if len(response.Keys) == 0 {
		fmt.Printf("No SSH keys found.\n")
	} else {
		fmt.Printf("Total keys: %d\n\n", response.Total)
		fmt.Printf("%-20s %-14s %-6s %-8s %-20s %-20s\n", "Username", "Type", "Bits", "Status", "Created", "Expires")
		fmt.Printf("%-20s %-14s %-6s %-8s %-20s %-20s\n",
			strings.Repeat("-", 20),
			strings.Repeat("-", 14),
			strings.Repeat("-", 6),
			strings.Repeat("-", 8),
			strings.Repeat("-", 20),
			strings.Repeat("-", 20))

		for _, key := range response.Keys {
			fmt.Printf("%-20s %-14s %-6d %-8s %-20s %-20s\n",
				truncateString(key.Username, 20),
				truncateString(key.KeyType, 14),
				key.KeySize,
				truncateString(key.Status, 8),
				key.CreatedAt.Format("2006-01-02 15:04:05"),
				key.ExpiresAt.Format("2006-01-02 15:04:05"))
		}
	}

	if response.Unreadable > 0 {
		fmt.Printf("\n⚠️  %d key director(y|ies) could not be read and are not listed above;\n", response.Unreadable)
		fmt.Printf("    see the broker log for details.\n")
	}

	return nil
}

// errBrokerUnreachable distinguishes "could not reach the broker" from "the
// broker answered with an error", which the status and health output report
// differently.
var errBrokerUnreachable = errors.New("broker unreachable")

// adminRequest sends one parameterless admin request and decodes the reply into
// out, which must be a pointer to one of the adminapi response types.
//
// One connection per request: the broker serves a single request per connection
// and then closes it.
func adminRequest(requestType string, out any) error {
	path := socketPath()

	conn, err := net.DialTimeout("unix", path, requestTimeout)
	if err != nil {
		return fmt.Errorf("%w: %w", errBrokerUnreachable, err)
	}
	defer func() { _ = conn.Close() }()

	// Bound the whole exchange, so a broker that accepts the connection and then
	// stops responding cannot hang the CLI indefinitely.
	if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return fmt.Errorf("failed to set request deadline: %w", err)
	}

	if err := json.NewEncoder(conn).Encode(map[string]any{"type": requestType}); err != nil {
		return fmt.Errorf("failed to send %s request: %w", requestType, err)
	}

	if err := json.NewDecoder(conn).Decode(out); err != nil {
		return fmt.Errorf("failed to decode %s response: %w", requestType, err)
	}

	// The broker reports refusals (including "you are not root") in the response
	// body, so a successful decode is not a successful request.
	if failable, ok := out.(interface{ Err() error }); ok {
		if err := failable.Err(); err != nil {
			return err
		}
	}

	return nil
}

func getBrokerStatus() (*adminapi.StatusResponse, error) {
	var response adminapi.StatusResponse
	if err := adminRequest("status", &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
