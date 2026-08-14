package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oidc-pam/internal/ipc"
	"github.com/scttfrdmn/oidc-pam/pkg/auth"
	"github.com/scttfrdmn/oidc-pam/pkg/config"
	oidcmetrics "github.com/scttfrdmn/oidc-pam/pkg/metrics"
)

var (
	version   = "dev"
	buildDate = "unknown"
	gitCommit = "unknown"
)

var (
	configPath  = flag.String("config", "/etc/oidc-auth/broker.yaml", "Path to configuration file")
	logLevel    = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	showVersion = flag.Bool("version", false, "Show version information")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("oidc-auth-broker version %s\n", version)
		fmt.Printf("  Build date: %s\n", buildDate)
		fmt.Printf("  Git commit: %s\n", gitCommit)
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

	// Report this binary's version through `oidc-admin status`; pkg/auth cannot
	// see the ldflags variable itself.
	broker.SetVersion(version)

	// Initialise Prometheus metrics and optionally start the /metrics endpoint.
	var metricsServer *oidcmetrics.Server
	if cfg.Server.MetricsAddr != "" {
		reg := prometheus.NewRegistry()
		m := oidcmetrics.New(reg, func() float64 {
			return float64(broker.DroppedAuditEvents())
		})
		broker.SetMetrics(m)
		metricsServer = oidcmetrics.NewServer(cfg.Server.MetricsAddr, reg)
		metricsServer.Start()
		log.Info().Str("addr", cfg.Server.MetricsAddr).Msg("Prometheus metrics endpoint enabled")
	}

	// Create IPC server for PAM communication
	ipcServer, err := ipc.NewServer(cfg.Server.SocketPath, broker, cfg.Server.SocketMode, cfg.Server.SocketGroup, cfg.Server.RequirePeerAuth, cfg.Security.RateLimiting.MaxRequestsPerMinute, cfg.Security.RateLimiting.MaxConcurrentAuths)
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

	// Keep a stray SIGHUP from taking the broker down (#224).
	ignoreSIGHUP()

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

		// Stop metrics server (if enabled).
		if metricsServer != nil {
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutCancel()
			if err := metricsServer.Stop(shutCtx); err != nil {
				log.Error().Err(err).Msg("Error stopping metrics server")
			}
		}

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

// ignoreSIGHUP stops a SIGHUP from terminating the broker.
//
// Go's default disposition for SIGHUP is to kill the process, and the broker has no
// configuration reload: the config is read once, at startup, before auth.NewBroker,
// and nothing re-reads it. So every SIGHUP the broker has ever received was a
// ten-second authentication outage for the whole host — Restart=always brings it
// back RestartSec=10s later — with nothing in the journal but a clean exit and a
// restart (#224).
//
// The shipped unit no longer advertises ExecReload=, so `systemctl reload` refuses
// the job outright. This handler covers what the unit cannot: a site's logrotate
// postrotate stanza, or an operator's `kill -HUP` on the daemon that holds
// /var/log/oidc-auth open. Those are the documented idiom for "reload your logs" and
// this repo does not control them.
//
// Swallowing the signal is deliberately not the same as implementing reload, and the
// log line says so: whoever sent it wanted new configuration to take effect and has
// to be told that only a restart does that.
func ignoreSIGHUP() {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Warn().Msg("Received SIGHUP and ignored it: the broker has no configuration " +
				"reload — configuration is read once at startup, so restart the service to " +
				"apply changes")
		}
	}()
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
