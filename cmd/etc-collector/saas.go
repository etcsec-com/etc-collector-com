package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/etcsec-com/etc-collector/internal/logger"
	"github.com/etcsec-com/etc-collector/internal/saas"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	// Import detectors to register them via init()
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad"
)

var (
	saasURL   string
	configDir string

	// allowInsecureSaaSURL opts out of the https requirement on the enrolment URL
	// (A_004 K8). Shared by `enroll` and `install` — see saas.ValidateSaaSURL.
	allowInsecureSaaSURL bool

	// LDAP override flags for daemon mode
	daemonLDAPURL       string
	daemonLDAPBindDN    string
	daemonLDAPBindPass  string
	daemonLDAPBaseDN    string
	daemonLDAPTLSVerify bool

	// Azure/Entra local certificate override for daemon mode (B_026, T_048) — never
	// cloud-managed, see saas.AzureOverrides
	daemonAzureClientCert     string
	daemonAzureClientCertPass string

	// Embedded GUI flags
	guiPort              int
	guiHost              string
	guiAllowInsecureHTTP bool

	// Update watcher flags (internal, used by "update watch" subcommand)
	watchPID       int
	watchBinary    string
	watchNewBinary string
	watchBackup    string
	watchStaging   string
	watchLogFile   string
)

// enrollCmd handles enrollment
var enrollCmd = &cobra.Command{
	Use:   "enroll [token]",
	Short: "Enroll this collector with the SaaS platform",
	Long: `Enroll this collector instance with the ETC Security SaaS platform.

You need an enrollment token from your organization's dashboard.
The token can be provided as an argument or via ETCSEC_ENROLL_TOKEN environment variable.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runEnroll,
}

// daemonCmd handles daemon mode
var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run in daemon mode (SaaS)",
	Long: `Run the collector in daemon mode for SaaS integration.

The collector must be enrolled first using the 'enroll' command.
In daemon mode, the collector polls the SaaS backend for commands
and reports audit results and health status.`,
	RunE: runDaemon,
}

// statusCmd shows enrollment status
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show enrollment status",
	RunE:  runStatus,
}

// unenrollCmd removes enrollment
var unenrollCmd = &cobra.Command{
	Use:   "unenroll",
	Short: "Remove enrollment from SaaS platform",
	Long: `Remove this collector's enrollment from the SaaS platform.

This notifies the backend (best-effort) and deletes local credentials.`,
	RunE: runUnenroll,
}

// updateCmd is the parent for update subcommands (hidden, internal)
var updateCmd = &cobra.Command{
	Use:    "update",
	Short:  "Update management (internal)",
	Hidden: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip root's PersistentPreRunE — watcher doesn't need config/logger
		return nil
	},
}

// updateWatchCmd is the watcher subprocess entry point.
// Invoked internally by the daemon as: etc-collector update watch --pid X ...
var updateWatchCmd = &cobra.Command{
	Use:    "watch",
	Short:  "Run as update watcher subprocess (internal)",
	Hidden: true,
	RunE:   runUpdateWatch,
}

func init() {
	rootCmd.AddCommand(enrollCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(unenrollCmd)

	// Enroll flags
	enrollCmd.Flags().StringVar(&saasURL, "saas-url", "", "SaaS API URL (required, https)")
	enrollCmd.Flags().StringVar(&configDir, "config-dir", "", "Config directory for credentials")
	enrollCmd.Flags().BoolVar(&allowInsecureSaaSURL, "allow-insecure-saas-url", false,
		"Allow a plaintext http:// SaaS URL (local test backends only — the enrollment token travels in the clear)")
	viper.BindEnv("saas.url", "ETCSEC_SAAS_URL")
	viper.BindEnv("enroll.token", "ETCSEC_ENROLL_TOKEN")

	// Daemon flags
	daemonCmd.Flags().StringVar(&configDir, "config-dir", "", "Config directory for credentials")
	daemonCmd.Flags().StringVar(&daemonLDAPURL, "ldap-url", "", "Override LDAP URL from SaaS config")
	daemonCmd.Flags().StringVar(&daemonLDAPBindDN, "ldap-bind-dn", "", "Override LDAP bind DN")
	daemonCmd.Flags().StringVar(&daemonLDAPBindPass, "ldap-bind-password", "", "Override LDAP bind password")
	daemonCmd.Flags().StringVar(&daemonLDAPBaseDN, "ldap-base-dn", "", "Override LDAP base DN")
	daemonCmd.Flags().BoolVar(&daemonLDAPTLSVerify, "ldap-tls-verify", true, "Override LDAP TLS verification")
	daemonCmd.Flags().StringVar(&daemonAzureClientCert, "azure-client-cert", "", "Path to a client certificate for Entra app-only auth (PEM bundle or PKCS#12/.pfx). Local to this host only — never transmitted to or received from the SaaS. Required for tenants that forbid client secrets; takes precedence over any cloud-managed client secret.")
	daemonCmd.Flags().StringVar(&daemonAzureClientCertPass, "azure-client-cert-password", "", "Password protecting --azure-client-cert (encrypted PKCS#12/.pfx)")
	daemonCmd.Flags().IntVar(&guiPort, "gui-port", 8443, "Local GUI server port (0 to disable)")
	daemonCmd.Flags().StringVar(&guiHost, "gui-host", "127.0.0.1", "GUI listen address (127.0.0.1 = local only, 0.0.0.0 = all interfaces)")
	daemonCmd.Flags().BoolVar(&guiAllowInsecureHTTP, "gui-allow-insecure-http", false, "Allow the admin GUI to serve plain HTTP on a non-loopback --gui-host (default: a bootstrap self-signed certificate is generated automatically and TLS is required). Every request served this way is logged.")

	// Status/Unenroll flags
	statusCmd.Flags().StringVar(&configDir, "config-dir", "", "Config directory for credentials")
	unenrollCmd.Flags().StringVar(&configDir, "config-dir", "", "Config directory for credentials")

	// Update watcher command (hidden, internal)
	rootCmd.AddCommand(updateCmd)
	updateCmd.AddCommand(updateWatchCmd)
	updateWatchCmd.Flags().IntVar(&watchPID, "pid", 0, "Parent PID to wait for")
	updateWatchCmd.Flags().StringVar(&watchBinary, "binary", "", "Path to current binary")
	updateWatchCmd.Flags().StringVar(&watchNewBinary, "new-binary", "", "Path to new binary")
	updateWatchCmd.Flags().StringVar(&watchBackup, "backup", "", "Backup path")
	updateWatchCmd.Flags().StringVar(&watchStaging, "staging", "", "Staging directory")
	updateWatchCmd.Flags().StringVar(&watchLogFile, "log-file", "", "Log file path")
	updateWatchCmd.MarkFlagRequired("pid")
	updateWatchCmd.MarkFlagRequired("binary")
	updateWatchCmd.MarkFlagRequired("new-binary")
	updateWatchCmd.MarkFlagRequired("backup")
	updateWatchCmd.MarkFlagRequired("staging")
	updateWatchCmd.MarkFlagRequired("log-file")
}

func runEnroll(cmd *cobra.Command, args []string) error {
	// Get token from args or env
	token := ""
	if len(args) > 0 {
		token = args[0]
	} else {
		token = viper.GetString("enroll.token")
	}

	if token == "" {
		return fmt.Errorf("enrollment token required (as argument or ETCSEC_ENROLL_TOKEN)")
	}

	// Resolve SaaS URL
	url := saasURL
	if url == "" {
		url = viper.GetString("saas.url")
	}
	if url == "" {
		return fmt.Errorf("SaaS URL required (--saas-url or ETCSEC_SAAS_URL)")
	}
	// A_004 K8 — refuse a cleartext enrolment (covers ETCSEC_SAAS_URL too).
	if err := saas.ValidateSaaSURL(url, allowInsecureSaaSURL); err != nil {
		return err
	}
	if saas.IsPlaintextSaaSURL(url) {
		log.Warn("Enrolling over PLAINTEXT HTTP — the enrolment token and every subsequent "+
			"command travel in the clear. Never use this against a production SaaS.", "url", url)
	}

	dir, err := resolveConfigDir()
	if err != nil {
		return err
	}

	daemon, err := saas.NewDaemon(dir, Version, Edition)
	if err != nil {
		return fmt.Errorf("create daemon: %w", err)
	}

	if daemon.IsEnrolled() {
		return fmt.Errorf("already enrolled. Run 'unenroll' first to re-enroll")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Info("Enrolling with SaaS platform", "url", url)

	if err := daemon.Enroll(ctx, token, url); err != nil {
		return err
	}

	// Load and display result
	creds, _ := daemon.LoadCredentials()
	if creds != nil {
		fmt.Printf("Enrolled successfully!\n")
		fmt.Printf("  Collector ID: %s\n", creds.CollectorID)
		fmt.Printf("  SaaS URL:     %s\n", creds.SaaSURL)
		if creds.Config.LDAP.IsConfigured() {
			fmt.Printf("  LDAP URL:     %s\n", creds.Config.LDAP.URL)
			fmt.Printf("  LDAP Base DN: %s\n", creds.Config.LDAP.BaseDN)
		}
		if creds.Config.Azure.IsConfigured() {
			fmt.Printf("  Azure Tenant: %s\n", creds.Config.Azure.TenantID)
		}
		if !creds.Config.LDAP.IsConfigured() && !creds.Config.Azure.IsConfigured() {
			fmt.Printf("  Providers:    none (configure via SaaS dashboard)\n")
		}
		fmt.Printf("\nRun 'daemon' to start the collector.\n")
	}

	return nil
}

func runDaemon(cmd *cobra.Command, args []string) error {
	// T_106 (follow-up to T_101/server.go): --ldap-bind-password puts the LDAP
	// bind secret in argv, readable by any local user via /proc/<pid>/cmdline for
	// as long as the process runs. This flag is a one-off local override
	// (daemonLDAPBindPass, applied below only if non-empty) — it is never read
	// back from viper, so LDAP_BIND_PASSWORD/config.yaml are not an alternative
	// here. The daemon's normal source of the LDAP bind password is the
	// SaaS-managed enrollment config (CredentialStore), which needs no flag at
	// all.
	if cmd.Flags().Changed("ldap-bind-password") {
		log.Warn("--ldap-bind-password was passed on the command line — the secret is readable by any local user for as long as this process runs (e.g. via /proc/<pid>/cmdline on Linux). This is meant only as a one-off local override; omit it and let the SaaS-managed enrollment config supply the LDAP bind password instead.")
	}

	dir, err := resolveConfigDir()
	if err != nil {
		return err
	}

	// B_042/T_041: SecureDir tightens permissions on a directory that already exists
	// at the looser 0755 — the state of every collector deployed before A_004 K7(b)
	// that was upgraded rather than reinstalled. CredentialStore.Save() alone never
	// reaches those, and a systemd restart after an in-place binary swap is the
	// realistic point where the fleet actually runs this code again, so it belongs
	// here, at daemon startup, not only inside Save().
	if err := saas.SecureDir(dir); err != nil {
		return fmt.Errorf("secure config directory: %w", err)
	}

	// Setup file logging for daemon mode (stdout + file, fallback to stderr)
	logFile := filepath.Join(dir, "collector.log")
	daemonLog, actualLogFile, err := logger.NewWithFileFallback("info", "console", logFile)
	if err != nil {
		log.Warn("Logger file init issue, using fallback", "error", err)
	}
	log = daemonLog
	logger.SetGlobal(daemonLog)

	// Startup banner — always written, even if daemon crashes immediately after
	log.Info("Starting daemon", "version", Version, "pid", os.Getpid())

	daemon, err := saas.NewDaemon(dir, Version, Edition)
	if err != nil {
		return fmt.Errorf("create daemon: %w", err)
	}
	if actualLogFile != "" {
		daemon.SetLogFile(actualLogFile)
	}

	if !daemon.IsEnrolled() {
		return fmt.Errorf("not enrolled. Run 'enroll' first")
	}

	// Apply LDAP overrides from CLI flags
	if daemonLDAPURL != "" || daemonLDAPBindDN != "" || daemonLDAPBindPass != "" || daemonLDAPBaseDN != "" || cmd.Flags().Changed("ldap-tls-verify") {
		overrides := &saas.LDAPOverrides{
			URL:          daemonLDAPURL,
			BindDN:       daemonLDAPBindDN,
			BindPassword: daemonLDAPBindPass,
			BaseDN:       daemonLDAPBaseDN,
		}
		if cmd.Flags().Changed("ldap-tls-verify") {
			overrides.TLSVerify = &daemonLDAPTLSVerify
		}
		daemon.LDAPOverrides = overrides
	}

	// Apply Azure/Entra local certificate override from CLI flags (B_026, T_048) —
	// never cloud-managed, see saas.AzureOverrides
	if daemonAzureClientCert != "" || daemonAzureClientCertPass != "" {
		daemon.AzureOverrides = &saas.AzureOverrides{
			ClientCertPath:     daemonAzureClientCert,
			ClientCertPassword: daemonAzureClientCertPass,
		}
	}

	// B_136 (T_060): explicit, logged opt-out from the TLS requirement on a
	// non-loopback --gui-host — see saas.AllowInsecureGUIHTTP.
	daemon.AllowInsecureGUIHTTP = guiAllowInsecureHTTP

	// If running as a Windows service, delegate to SCM handler
	if isWindowsServiceContext() {
		return runDaemonAsWindowsService(daemon)
	}

	// Regular CLI mode
	log.Info("Starting daemon mode", "version", Version)

	if err := daemon.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}

	// Start embedded GUI server (unless disabled with --gui-port 0). Gui-token
	// generation, if needed, happens inside StartEmbeddedGUI so it also covers the
	// Windows service entrypoint (daemon_windows.go), which calls it directly.
	if guiPort > 0 {
		if err := daemon.StartEmbeddedGUI(guiHost, guiPort); err != nil {
			return fmt.Errorf("start embedded GUI: %w", err)
		}
	}

	// Block on signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Info("Received shutdown signal", "signal", sig.String())

	return daemon.Stop()
}

func runStatus(cmd *cobra.Command, args []string) error {
	dir, err := resolveConfigDir()
	if err != nil {
		return err
	}
	credStore := saas.NewCredentialStore(dir)

	if !credStore.Exists() {
		fmt.Println("Status: Not enrolled")
		fmt.Printf("Config dir: %s\n", dir)
		return nil
	}

	creds, err := credStore.Load()
	if err != nil {
		return fmt.Errorf("load credentials: %w", err)
	}

	fmt.Println("Status: Enrolled")
	fmt.Printf("  Collector ID:  %s\n", creds.CollectorID)
	fmt.Printf("  SaaS URL:      %s\n", creds.SaaSURL)
	if creds.Config.LDAP.IsConfigured() {
		fmt.Printf("  LDAP URL:      %s\n", creds.Config.LDAP.URL)
		fmt.Printf("  LDAP Base DN:  %s\n", creds.Config.LDAP.BaseDN)
	}
	if creds.Config.Azure.IsConfigured() {
		fmt.Printf("  Azure Tenant:  %s\n", creds.Config.Azure.TenantID)
	}
	if !creds.Config.LDAP.IsConfigured() && !creds.Config.Azure.IsConfigured() {
		fmt.Printf("  Providers:     none (configure via SaaS dashboard)\n")
	}
	fmt.Printf("  Poll interval: %ds\n", creds.Config.Polling.IntervalSeconds)
	fmt.Printf("  Credentials:   %s\n", credStore.Path())

	return nil
}

func runUnenroll(cmd *cobra.Command, args []string) error {
	dir, err := resolveConfigDir()
	if err != nil {
		return err
	}

	daemon, err := saas.NewDaemon(dir, Version, Edition)
	if err != nil {
		return fmt.Errorf("create daemon: %w", err)
	}

	if !daemon.IsEnrolled() {
		fmt.Println("Not enrolled, nothing to do.")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := daemon.UnenrollRemote(ctx); err != nil {
		return fmt.Errorf("unenroll failed: %w", err)
	}

	fmt.Println("Unenrolled successfully. Credentials removed.")
	return nil
}

func runUpdateWatch(cmd *cobra.Command, args []string) error {
	saas.RunWatcher(saas.WatcherParams{
		PID:       watchPID,
		Binary:    watchBinary,
		NewBinary: watchNewBinary,
		Backup:    watchBackup,
		Staging:   watchStaging,
		LogFile:   watchLogFile,
	})
	return nil
}

// resolveConfigDir returns the config directory, respecting flags and env.
// Errors instead of falling back to a path relative to the current directory —
// see saas.DefaultConfigDir (A_004 K7(e)).
func resolveConfigDir() (string, error) {
	if configDir != "" {
		return configDir, nil
	}
	return saas.DefaultConfigDir()
}
