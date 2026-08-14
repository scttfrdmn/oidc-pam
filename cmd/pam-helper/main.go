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
	"github.com/scttfrdmn/oidc-pam/internal/brokerclient"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/pkg/pam"
)

// Version information
var (
	version   = "dev"
	buildDate = "unknown"
	gitCommit = "unknown"
)

const (
	Name = "oidc-pam-helper"

	// watchdogGrace is how much longer than the authentication timeout the
	// outer watchdog waits before giving up on AuthenticateUser.
	watchdogGrace = 10 * time.Second
)

func main() {
	// Parse command line flags
	var (
		configFile = flag.String("config", "/etc/oidc-auth/pam.conf", "Path to configuration file")
		username   = flag.String("user", "", "Username to authenticate")
		service    = flag.String("service", "unknown", "Service requesting authentication")
		// (#169) Defaults to empty, not "localhost": rhost becomes the request's
		// source_ip, and inventing a peer for a login that has none is the mistake
		// this flag would otherwise hand the broker.
		rhost       = flag.String("rhost", "", "Address the login is coming from (PAM_RHOST); empty for a local login")
		tty         = flag.String("tty", "unknown", "TTY")
		debug       = flag.Bool("debug", false, "Enable debug logging")
		showVersion = flag.Bool("version", false, "Show version information")
		socketPath  = flag.String("socket", "/var/run/oidc-auth/broker.sock", "Path to broker socket")
		timeout     = flag.Duration("timeout", brokerclient.DefaultAuthTimeout, "How long to wait for the user to complete the device authorization flow")
		_           = flag.Bool("interactive", false, "Interactive mode (prompt for user input)")
	)
	flag.Parse()

	// Show version information
	if *showVersion {
		fmt.Printf("%s version %s\n", Name, version)
		fmt.Printf("  Build date: %s\n", buildDate)
		fmt.Printf("  Git commit: %s\n", gitCommit)
		os.Exit(0)
	}

	// L-6: when running privileged (EUID 0), ignore caller-supplied -config and
	// -socket and force the compiled defaults. Otherwise a privileged invocation
	// with attacker-controlled argv could point the helper at a rogue broker
	// socket (which could answer success) or a rogue config.
	const (
		defaultConfigPath = "/etc/oidc-auth/pam.conf"
		defaultSocketPath = "/var/run/oidc-auth/broker.sock"
	)
	if os.Geteuid() == 0 {
		if *configFile != defaultConfigPath {
			log.Warn().Str("ignored", *configFile).Msg("Ignoring caller-supplied -config while running as root; using default")
			*configFile = defaultConfigPath
		}
		if *socketPath != defaultSocketPath {
			log.Warn().Str("ignored", *socketPath).Msg("Ignoring caller-supplied -socket while running as root; using default")
			*socketPath = defaultSocketPath
		}
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
		Str("version", version).
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
	pamModule.AuthTimeout = *timeout

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

	// A watchdog, not the authentication timeout: AuthenticateUser enforces
	// *timeout itself and reports the expiry as a denial. The extra grace lets
	// that specific error win the race, so the log says why the login failed.
	case <-time.After(*timeout + watchdogGrace):
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
