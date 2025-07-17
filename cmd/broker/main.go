package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/pkg/auth"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	"github.com/scttfrdmn/oidc-pam/internal/ipc"
)

const (
	version = "0.1.0-alpha"
)

var (
	configPath = flag.String("config", "/etc/oidc-auth/broker.yaml", "Path to configuration file")
	logLevel   = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	showVersion = flag.Bool("version", false, "Show version information")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("oidc-auth-broker version %s\n", version)
		os.Exit(0)
	}

	// Initialize logging
	setupLogging(*logLevel)

	log.Info().
		Str("version", version).
		Str("config", *configPath).
		Msg("Starting OIDC Authentication Broker")

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("config_path", *configPath).
			Msg("Failed to load configuration")
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatal().
			Err(err).
			Msg("Invalid configuration")
	}

	// Create authentication broker
	broker, err := auth.NewBroker(cfg)
	if err != nil {
		log.Fatal().
			Err(err).
			Msg("Failed to create authentication broker")
	}

	// Create IPC server for PAM communication
	ipcServer, err := ipc.NewServer(cfg.Server.SocketPath, broker)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("socket_path", cfg.Server.SocketPath).
			Msg("Failed to create IPC server")
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start broker services
	if err := broker.Start(ctx); err != nil {
		log.Fatal().
			Err(err).
			Msg("Failed to start broker services")
	}

	// Start IPC server
	if err := ipcServer.Start(ctx); err != nil {
		log.Fatal().
			Err(err).
			Msg("Failed to start IPC server")
	}

	log.Info().
		Str("socket_path", cfg.Server.SocketPath).
		Msg("OIDC Authentication Broker started successfully")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	log.Info().Msg("Received shutdown signal, initiating graceful shutdown...")

	// Cancel context to trigger graceful shutdown
	cancel()

	// Give services time to shutdown gracefully
	shutdownTimer := time.NewTimer(30 * time.Second)
	defer shutdownTimer.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		
		// Stop IPC server
		if err := ipcServer.Stop(); err != nil {
			log.Error().
				Err(err).
				Msg("Error stopping IPC server")
		}

		// Stop broker services
		if err := broker.Stop(); err != nil {
			log.Error().
				Err(err).
				Msg("Error stopping broker services")
		}
	}()

	select {
	case <-done:
		log.Info().Msg("Graceful shutdown completed")
	case <-shutdownTimer.C:
		log.Warn().Msg("Shutdown timeout exceeded, forcing exit")
	}

	log.Info().Msg("OIDC Authentication Broker stopped")
}

func setupLogging(level string) {
	// Configure zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	
	// Set log level
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("level", level).
			Msg("Invalid log level")
	}
	zerolog.SetGlobalLevel(logLevel)

	// Configure console output for development
	if os.Getenv("OIDC_AUTH_DEV") == "true" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
}