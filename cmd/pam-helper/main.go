package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/pam"
)

// Version information
const (
	Version = "0.1.0-alpha"
	Name    = "oidc-pam-helper"
)

func main() {
	// Parse command line flags
	var (
		configFile  = flag.String("config", "/etc/oidc-auth/pam.conf", "Path to configuration file")
		username    = flag.String("user", "", "Username to authenticate")
		service     = flag.String("service", "unknown", "Service requesting authentication")
		rhost       = flag.String("rhost", "localhost", "Remote host")
		tty         = flag.String("tty", "unknown", "TTY")
		debug       = flag.Bool("debug", false, "Enable debug logging")
		version     = flag.Bool("version", false, "Show version information")
		socketPath  = flag.String("socket", "/var/run/oidc-auth/broker.sock", "Path to broker socket")
		timeout     = flag.Duration("timeout", 30*time.Second, "Authentication timeout")
		_ = flag.Bool("interactive", false, "Interactive mode (prompt for user input)")
	)
	flag.Parse()

	// Show version information
	if *version {
		fmt.Printf("%s version %s\n", Name, Version)
		os.Exit(0)
	}

	// Set up logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	log.Info().
		Str("version", Version).
		Str("config", *configFile).
		Bool("debug", *debug).
		Msg("Starting OIDC PAM Helper")

	// Validate required parameters
	if *username == "" {
		log.Fatal().Msg("Username is required")
	}

	// Load configuration
	_, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Use provided socket path or default
	finalSocketPath := *socketPath
	if finalSocketPath == "" {
		finalSocketPath = "/var/run/oidc-auth/broker.sock"
	}

	// Create PAM module
	pamModule := pam.NewPAMModule(finalSocketPath, *debug)

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create a timeout context
	done := make(chan bool, 1)
	var authError error

	// Start authentication in a goroutine
	go func() {
		defer func() {
			done <- true
		}()

		log.Info().
			Str("username", *username).
			Str("service", *service).
			Str("rhost", *rhost).
			Str("tty", *tty).
			Msg("Starting authentication")

		// Perform authentication
		authError = pamModule.AuthenticateUser(*username, *service, *rhost, *tty)
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		// Authentication completed
		if authError != nil {
			log.Error().Err(authError).Msg("Authentication failed")
			os.Exit(1)
		}
		log.Info().
			Str("username", *username).
			Msg("Authentication successful")
		os.Exit(0)

	case <-time.After(*timeout):
		log.Error().
			Dur("timeout", *timeout).
			Msg("Authentication timed out")
		os.Exit(1)

	case sig := <-sigChan:
		log.Info().
			Str("signal", sig.String()).
			Msg("Received signal, shutting down")
		os.Exit(1)
	}
}

// Helper function to prompt user for input (for interactive mode)
func promptUser(prompt string) (string, error) {
	fmt.Print(prompt)
	var input string
	_, err := fmt.Scanln(&input)
	return input, err
}

// Helper function to display instructions to user
func displayInstructions(instructions string) {
	fmt.Printf("\n%s\n", instructions)
}

// Helper function to check if running in interactive terminal
func isInteractive() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// Helper function to get environment variable with default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}