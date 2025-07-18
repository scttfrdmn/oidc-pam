package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	version   = "dev"
	buildDate = "unknown"
	gitCommit = "unknown"
)

const (
	AppName = "oidc-admin"
)

var (
	cfgFile string
	debug   bool
	verbose bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   AppName,
	Short: "OIDC PAM Administration Tool",
	Long: `OIDC Admin is a command-line tool for managing the OIDC PAM authentication system.
	
It provides functionality for:
- Managing user sessions and tokens
- Configuring OIDC providers
- Monitoring system health
- Managing SSH keys
- Viewing audit logs
- System diagnostics`,
	Version: fmt.Sprintf("%s (built %s, commit %s)", version, buildDate, gitCommit),
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/oidc-auth/broker.yaml)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable verbose output")

	// Bind flags to viper
	_ = viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

// initConfig reads in config file and ENV variables
func initConfig() {
	// Setup logging
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("/etc/oidc-auth")
		viper.AddConfigPath("$HOME/.oidc-auth")
		viper.AddConfigPath(".")
		viper.SetConfigName("broker")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	// If a config file is found, read it in
	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			log.Info().Str("config", viper.ConfigFileUsed()).Msg("Using config file")
		}
	}
}

