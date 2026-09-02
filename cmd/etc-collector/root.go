package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/logger"
)

var (
	cfgFile string
	verbose bool
	cfg     *config.Config
	log     *logger.Logger
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "etc-collector",
	Short: "Active Directory Security Auditing Tool",
	Long: `ETC Collector is a security auditing tool for Active Directory
and Azure AD / Entra ID environments.

It performs over 500 security checks to identify
misconfigurations, vulnerabilities, and attack paths.`,
	Version: Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip init for version and help
		if cmd.Name() == "version" || cmd.Name() == "help" {
			return nil
		}

		// Load configuration FIRST — B_033 (T_038). The logger used to be built
		// before this, from a hardcoded "info"/"console", which is why the log:
		// section of config.yaml was parsed, echoed back by /admin/config and never
		// applied: by the time the file was read, the logger already existed.
		var err error
		var cfgErr error
		cfg, cfgErr = config.Load(cfgFile)
		if cfgErr != nil {
			cfg = config.Default()
		}

		// Precedence: CLI flag > environment > config.yaml > built-in default.
		// See internal/config/precedence.go for the canonical rule.
		flagLevel := ""
		if verbose {
			flagLevel = "debug"
		}
		logLevel := config.Resolve(flagLevel, os.Getenv("ETCSEC_LOG_LEVEL"), cfg.Log.Level, "info")
		logFormat := config.Resolve(os.Getenv("ETCSEC_LOG_FORMAT"), cfg.Log.Format, "console")

		log, err = logger.New(logLevel, logFormat)
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}

		// Deferred until the logger exists, so the warning is not lost.
		if cfgErr != nil {
			log.Warn("Failed to load config file, using defaults", "error", cfgErr)
		}

		return nil
	},
}

// Execute runs the root command
func Execute() error {
	// Set version string to include edition (e.g., "2.8.0 (pro)" or "2.8.0 (community)")
	// Plus de suffixe d'edition depuis la v3.2.0 : il n'y en a plus qu'une.
	// Afficher « (pro) » a un utilisateur qui n'a jamais eu le choix le laisse
	// chercher une edition « community » qui n'existe plus. La variable Edition
	// survit uniquement pour le format de fil envoye au cloud (voir main.go).
	rootCmd.Version = Version
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "V", false, "enable verbose/debug output")

	// Bind to viper
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in current directory
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/etc-collector")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// Environment variables
	viper.SetEnvPrefix("ETCSEC")
	viper.AutomaticEnv()

	// Read config
	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}
}
