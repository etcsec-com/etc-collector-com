package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/etcsec-com/etc-collector/internal/api"
	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/guitoken"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/internal/providers/ldap"
	"github.com/etcsec-com/etc-collector/internal/providers/smb"
	"github.com/etcsec-com/etc-collector/internal/saas"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	// Import detectors to register them via init()
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad"
)

var (
	serverPort              int
	serverHost              string
	serverAllowInsecureHTTP bool
	serverConfigDirFlag     string
	ldapURL                 string
	ldapBindDN              string
	ldapBindPass            string
	ldapBaseDN              string
	ldapTLSVerify           bool
	enableNetworkProbes     bool
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Manage the local admin GUI & API server",
	Long: `Manage the local admin GUI and REST API server.

The admin GUI lets you view audit results, configure LDAP/Azure
connections, and trigger audits from your browser. It runs alongside
the SaaS daemon — both work at the same time.

QUICK START (SaaS mode):
  sudo etc-collector server enable               # local access (127.0.0.1:8443)
  sudo etc-collector server enable --host 0.0.0.0 # network access

  Then open the GUI (see TLS below for http:// vs https://) and enter your
  GUI access token.

COMMANDS:
  enable    Enable the admin GUI (updates service, generates token, restarts)
  disable   Disable the admin GUI (SaaS daemon keeps running)

STANDALONE MODE (no SaaS):
  etc-collector server --port 8443                # start in foreground

OPTIONS:
  --host     Listen address: 127.0.0.1 (local only, default) or 0.0.0.0 (all interfaces)
  --port     Server port (default: 8443)

TLS: a non-loopback --host requires TLS. If server.tlsCertFile/tlsKeyFile
  aren't set in config.yaml, a bootstrap self-signed certificate is generated
  automatically (browsers will warn — it isn't signed by a public CA) and the
  GUI serves https://. Pass --allow-insecure-http to serve plain http://
  instead; this is logged loudly on every start.

TESTING (foreground, Ctrl+C to stop):
  etc-collector daemon --gui-host 0.0.0.0 --gui-port 8443

GUI ACCESS TOKEN:
  The GUI is protected by an access token. It is generated automatically
  on first 'server enable' or 'install'. To reset:
    etc-collector gui-token reset

FIREWALL:
  If using --host 0.0.0.0, open the port in your firewall:
    sudo firewall-cmd --add-port=8443/tcp --permanent && sudo firewall-cmd --reload`,
	Aliases: []string{"serve", "start"},
	RunE:    runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Server flags
	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 8443, "API server port")
	serverCmd.Flags().StringVar(&serverHost, "host", "127.0.0.1", "Listen address: 127.0.0.1 (local only) or 0.0.0.0 (all interfaces). B_136 (T_060): a non-loopback host requires TLS — a bootstrap self-signed certificate is generated automatically unless --allow-insecure-http is set.")
	serverCmd.Flags().BoolVar(&serverAllowInsecureHTTP, "allow-insecure-http", false, "Allow serving plain HTTP on a non-loopback --host (default: TLS is required, auto-provisioned if not configured). Every request served this way is logged.")
	serverCmd.Flags().StringVar(&ldapURL, "ldap-url", "", "LDAP server URL (e.g., ldaps://dc.example.com:636)")
	serverCmd.Flags().StringVar(&ldapBindDN, "ldap-bind-dn", "", "LDAP bind DN")
	serverCmd.Flags().StringVar(&ldapBindPass, "ldap-bind-password", "", "LDAP bind password")
	serverCmd.Flags().StringVar(&ldapBaseDN, "ldap-base-dn", "", "LDAP base DN for searches")
	serverCmd.Flags().BoolVar(&ldapTLSVerify, "ldap-tls-verify", true, "Verify LDAP TLS certificates")
	serverCmd.Flags().BoolVar(&enableNetworkProbes, "enable-network-probes", false, "Enable network probes (HTTP for ADCS ESC8, DNS zone transfer)")
	serverCmd.Flags().StringVar(&serverConfigDirFlag, "config-dir", "", "Directory holding config.yaml, keys/, and tls/ (default: wherever the global --config points, or /etc/etc-collector). Also settable via ETCSEC_CONFIG_DIR (B_092, T_067) — the flag wins if both are set.")

	// Bind to viper
	viper.BindPFlag("server.port", serverCmd.Flags().Lookup("port"))
	viper.BindPFlag("server.host", serverCmd.Flags().Lookup("host"))
	viper.BindPFlag("server.configDir", serverCmd.Flags().Lookup("config-dir"))
	viper.BindPFlag("ldap.url", serverCmd.Flags().Lookup("ldap-url"))
	viper.BindPFlag("ldap.bindDN", serverCmd.Flags().Lookup("ldap-bind-dn"))
	viper.BindPFlag("ldap.bindPassword", serverCmd.Flags().Lookup("ldap-bind-password"))
	viper.BindPFlag("ldap.baseDN", serverCmd.Flags().Lookup("ldap-base-dn"))
	viper.BindPFlag("ldap.tlsVerify", serverCmd.Flags().Lookup("ldap-tls-verify"))
	viper.BindPFlag("features.networkProbes", serverCmd.Flags().Lookup("enable-network-probes"))

	// Environment variable bindings
	viper.BindEnv("ldap.url", "LDAP_URL")
	viper.BindEnv("ldap.bindDN", "LDAP_BIND_DN")
	viper.BindEnv("ldap.bindPassword", "LDAP_BIND_PASSWORD")
	viper.BindEnv("ldap.baseDN", "LDAP_BASE_DN")
	viper.BindEnv("ldap.tlsVerify", "LDAP_TLS_VERIFY")
	viper.BindEnv("server.port", "PORT")
	viper.BindEnv("server.configDir", "ETCSEC_CONFIG_DIR")
	viper.BindEnv("server.host", "HOST")
	viper.BindEnv("features.networkProbes", "ENABLE_NETWORK_PROBES")
}

func runServer(cmd *cobra.Command, args []string) error {
	// B_184 (T_089): this command had NO Windows SCM integration at all — a service
	// whose ImagePath ran `<bin> server` directly (install_windows.go's
	// installWindowsSCMService, mode="server") would fail with error 1053 ("the
	// service did not respond to the start or control request in a timely
	// fashion") the instant anyone tried to start it, since nothing here ever calls
	// svc.Run to report status back to the Service Control Manager. Confirmed live
	// on a lab Windows Server host with a throwaway test service: the exact same
	// binary serves requests fine when run any other way, and cleanly exits with
	// no orphaned process — the
	// failure is specifically the missing SCM handshake, not a broken server.
	// runServerAsWindowsService (service_windows.go) reuses windowsService.Execute,
	// the implementation `etc-collector service run` already had working correctly
	// under its own (now-retired) service identity — same mechanism, canonical name.
	// Known gap this doesn't close: windowsService.Execute loads config.yaml from
	// its own working-directory-relative path and does not go through the
	// --config-dir/ETCSEC_CONFIG_DIR resolution below (B_092) — pre-existing, not
	// worsened here, flagged rather than silently left unstated.
	if isWindowsServiceContext() {
		return runServerAsWindowsService()
	}

	// T_101: --ldap-bind-password puts the domain bind secret in argv, readable by
	// any local user via /proc/<pid>/cmdline (world-readable on Linux, confirmed
	// live on a lab host) for as long as the process runs — not a transient
	// exposure. LDAP_BIND_PASSWORD (env, bound below) and ldap.bindPassword
	// (config.yaml, loaded below) both already avoid this; the flag stays only for
	// backward compatibility with existing invocations, now called out loudly
	// rather than silently accepted as equally safe.
	if cmd.Flags().Changed("ldap-bind-password") {
		log.Warn("--ldap-bind-password was passed on the command line — the secret is readable by any local user for as long as this process runs (e.g. via /proc/<pid>/cmdline on Linux). Prefer the LDAP_BIND_PASSWORD environment variable or ldap.bindPassword in config.yaml instead.")
	}

	// B_092 (T_067): --config-dir / ETCSEC_CONFIG_DIR had no effect on this startup
	// path at all — this mode read config.yaml only via viper's own default search
	// (the global --config flag, or "." and /etc/etc-collector). Flag wins over env
	// when both are set (viper's own precedence, the same flag>env>file order every
	// other setting in this function already follows — e.g. --host/HOST above).
	// Re-points viper's config file BEFORE any of the viper.GetX calls below, so all
	// of them, and configPath further down (which anchors keys/ and tls/), reflect
	// the redirected location.
	if dir := viper.GetString("server.configDir"); dir != "" {
		viper.SetConfigFile(filepath.Join(dir, "config.yaml"))
		if err := viper.ReadInConfig(); err != nil {
			// A missing config.yaml under a fresh --config-dir is the normal case on
			// a new install, not a failure — but note the two DIFFERENT shapes this
			// arrives in: SetConfigFile + ReadInConfig against a path that doesn't
			// exist returns a plain *fs.PathError, NOT viper.ConfigFileNotFoundError
			// (that type is only for the AddConfigPath+SetConfigName "searched
			// several paths, found nothing" case — config.Load uses that one; this
			// is the same trap T_048's resolveAuthTokenLifetime already hit once).
			var notFoundErr viper.ConfigFileNotFoundError
			isNotFound := errors.As(err, &notFoundErr) || os.IsNotExist(err)
			if !isNotFound {
				return fmt.Errorf("read config.yaml from --config-dir %s: %w", dir, err)
			}
			log.Warn("No config.yaml found under --config-dir, using defaults", "dir", dir)
		}
	}

	log.Info("Starting ETC Collector server",
		"version", Version,
		"port", viper.GetInt("server.port"),
	)

	// Create configuration
	cfg := config.Default()
	cfg.Server.Port = viper.GetInt("server.port")
	// B_136 (T_060): this used to be hardcoded to "0.0.0.0" regardless of any --host
	// flag — because there was no --host flag, despite this command's own --help text
	// documenting one. 127.0.0.1 by default (matching `server enable`'s own default
	// and the documented QUICK START); --host 0.0.0.0 opts into network exposure.
	cfg.Server.Host = viper.GetString("server.host")
	cfg.Server.Environment = "production"
	cfg.LDAP.URL = viper.GetString("ldap.url")
	cfg.LDAP.BindDN = viper.GetString("ldap.bindDN")
	cfg.LDAP.BindPassword = viper.GetString("ldap.bindPassword")
	cfg.LDAP.BaseDN = viper.GetString("ldap.baseDN")
	cfg.LDAP.TLSVerify = viper.GetBool("ldap.tlsVerify")
	// B_037 (T_038): this line used to be `cfg.LDAP.Timeout = 30 * time.Second`,
	// unconditionally discarding whatever ldap.timeout said — while /admin/config
	// echoed the file's value back to the operator. config.Default() already supplies
	// the same 30s, so a file that omits the key is unchanged.
	cfg.LDAP.Timeout = config.ResolveDuration(30*time.Second, viper.GetDuration("ldap.timeout"), cfg.LDAP.Timeout)
	cfg.Features.NetworkProbes = viper.GetBool("features.networkProbes")
	// B_047 (T_048): same defect as ldap.timeout above, same fix — this line was simply
	// missing, so auth.tokenLifetime stayed at config.Default()'s 30 days regardless of
	// what config.yaml said, on this the standalone-server startup path.
	cfg.Auth.TokenLifetime = config.ResolveDuration(cfg.Auth.TokenLifetime, viper.GetDuration("auth.tokenLifetime"))

	// Resolve config file path for persistence
	configPath := viper.ConfigFileUsed()
	if configPath == "" {
		configPath = "/etc/etc-collector/config.yaml"
	}

	// B_136 (T_060): server.tlsEnabled/tlsCertFile/tlsKeyFile were never read on this
	// startup path either — the third case of the exact same defect in this function
	// (ldap.timeout, then auth.tokenLifetime, now this). A non-loopback host requires
	// TLS; resolveGUITLS auto-provisions a bootstrap self-signed certificate when none
	// is configured, so this doesn't turn into a startup refusal for anyone already
	// running --host 0.0.0.0 today — see resolveGUITLS's doc for the full arbitrage.
	cfg.Server.TLSEnabled = viper.GetBool("server.tlsEnabled")
	cfg.Server.TLSCertFile = viper.GetString("server.tlsCertFile")
	cfg.Server.TLSKeyFile = viper.GetString("server.tlsKeyFile")
	tlsEnabled, tlsCertFile, tlsKeyFile, autoGenerated, err := saas.ResolveGUITLS(
		cfg.Server.Host, cfg.Server.TLSEnabled, cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile,
		filepath.Join(filepath.Dir(configPath), "tls"), serverAllowInsecureHTTP,
	)
	if err != nil {
		return fmt.Errorf("establish TLS for the admin server on %s:%d: %w (pass --allow-insecure-http to run without TLS instead)",
			cfg.Server.Host, cfg.Server.Port, err)
	}
	cfg.Server.TLSEnabled = tlsEnabled
	cfg.Server.TLSCertFile = tlsCertFile
	cfg.Server.TLSKeyFile = tlsKeyFile
	switch {
	case autoGenerated:
		log.Warn("Admin server is bound to a non-loopback interface with no certificate configured — generated a bootstrap self-signed one",
			"host", cfg.Server.Host, "port", cfg.Server.Port, "certFile", tlsCertFile)
	case !tlsEnabled && !saas.IsLoopbackHost(cfg.Server.Host):
		log.Warn("Admin server is serving PLAINTEXT HTTP on a network-reachable interface (--allow-insecure-http) — the admin token travels unencrypted",
			"host", cfg.Server.Host, "port", cfg.Server.Port)
	}

	// B_084 (T_067): JWT keys were never actually GENERATED on this startup path —
	// ensureKeys only ever tried to LOAD existing files and, on a fresh install with
	// none, logged an "openssl genrsa" instruction and gave up, leaving
	// cfg.Auth.PrivateKey nil. Every POST /api/v1/auth/token then failed with 500
	// token_generation_failed (pkg/types.GenerateToken refuses a nil key) — all 8
	// authMiddleware routes were unreachable as a direct consequence, since none of
	// them have a valid JWT to present. Same generator daemon mode already uses
	// (saas.EnsureJWTKeys, mirrors the exact bootstrap-on-demand model as the TLS
	// certificate above), anchored under configPath's directory so it doesn't depend
	// on the process's current working directory the way config.Default()'s bare
	// "./keys" path did.
	keysDir := filepath.Join(filepath.Dir(configPath), "keys")
	cfg.Auth.JWTPrivateKeyPath = filepath.Join(keysDir, "private.pem")
	cfg.Auth.JWTPublicKeyPath = filepath.Join(keysDir, "public.pem")
	if err := saas.EnsureJWTKeys(keysDir); err != nil {
		log.Warn("Failed to generate JWT keys — token auth will be unavailable", "error", err)
	}
	if err := cfg.LoadKeys(); err != nil {
		log.Warn("Failed to load JWT keys", "error", err)
	}

	// Create context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Info("Received shutdown signal", "signal", sig.String())
		cancel()
	}()

	// Create provider manager
	manager := providers.NewManager()

	// Initialize LDAP provider if configured
	ldapURLValue := cfg.LDAP.URL
	if ldapURLValue != "" {
		log.Info("Connecting to LDAP...", "url", ldapURLValue, "baseDN", cfg.LDAP.BaseDN)

		ldapProvider, err := ldap.NewClient(ldap.Config{
			URL:           cfg.LDAP.URL,
			BindDN:        cfg.LDAP.BindDN,
			BindPassword:  cfg.LDAP.BindPassword,
			BaseDN:        cfg.LDAP.BaseDN,
			TLSVerify:     cfg.LDAP.TLSVerify,
			TLSCACert:     cfg.LDAP.TLSCACert,
			TLSCACertPEM:  cfg.LDAP.TLSCACertPEM,
			TLSMinVersion: cfg.LDAP.TLSMinVersion,
			StartTLS:      cfg.LDAP.StartTLS,
			Timeout:       cfg.LDAP.Timeout,
		})
		if err != nil {
			log.Warn("Failed to create LDAP client, starting without LDAP", "error", err)
		} else if err := ldapProvider.Connect(ctx); err != nil {
			log.Warn("Failed to connect to LDAP, starting without LDAP", "error", err)
		} else {
			log.Info("LDAP connection successful")
			manager.Register(ldapProvider)
		}
	} else {
		log.Info("No LDAP configured — configure via GUI at http://localhost:" + fmt.Sprintf("%d", cfg.Server.Port))
	}

	// Create and start API server
	server := api.NewServer(cfg, manager)
	server.SetConfigPath(configPath)
	server.SetVersionInfo(Version, Edition)

	// Load (or generate) GUI access token hash. T_041/B_040: the admin API is
	// fail-closed with no hash configured, so ensure one exists before Start() can
	// accept a request — an upgraded-not-reinstalled install would otherwise be
	// locked out of its own admin API.
	guiConfigDir := filepath.Dir(configPath)
	hash, token, generated, err := guitoken.EnsureHash(guiConfigDir)
	if err != nil {
		return fmt.Errorf("ensure GUI access token: %w", err)
	}
	server.SetGuiTokenHash(hash)
	if generated {
		// B_135 (T_060): the token itself must never reach this logger — it also writes
		// to collector.log, which GET_LOGS can return over the SaaS channel. See
		// guitoken.AnnounceFirstRun for where the token actually goes.
		log.Warn("No GUI access token was configured — generated one now so the admin API stays protected. See stdout or <configDir>/gui-token.firstrun for the token.")
		if err := guitoken.AnnounceFirstRun(guiConfigDir, token); err != nil {
			log.Error("Failed to write gui-token.firstrun", "error", err)
		}
		log.Warn("To reset later: etc-collector gui-token reset")
	} else {
		log.Info("GUI access token protection enabled")
	}

	// Try to connect SMB for SYSVOL data (optional)
	if ldapURLValue != "" {
		smbServer := extractServerFromURL(cfg.LDAP.URL)
		smbDomain := extractDomainFromBaseDN(cfg.LDAP.BaseDN)
		smbUsername := extractUsernameFromBindDN(cfg.LDAP.BindDN)

		if smbServer != "" {
			smbClient := smb.NewClient(smb.Config{
				Server:   smbServer,
				Domain:   smbDomain,
				Username: smbUsername,
				Password: cfg.LDAP.BindPassword,
			})
			if err := smbClient.Connect(ctx); err != nil {
				log.Warn("SMB/SYSVOL connection failed, continuing without SYSVOL data", "error", err)
			} else {
				log.Info("SMB/SYSVOL connection successful")
				server.SetSYSVOLProvider(smbClient)
				defer smbClient.Close()
			}
		}
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	// Wait for shutdown or error
	select {
	case <-ctx.Done():
		log.Info("Shutting down server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// extractServerFromURL extracts the server address from an LDAP URL
// e.g., "ldaps://192.0.2.1:636" -> "192.0.2.1" (192.0.2.0/24 is the RFC 5737
// documentation range — not a real host)
func extractServerFromURL(ldapURL string) string {
	// Remove scheme
	s := ldapURL
	for _, prefix := range []string{"ldaps://", "ldap://", "LDAPS://", "LDAP://"} {
		if len(s) > len(prefix) && s[:len(prefix)] == prefix {
			s = s[len(prefix):]
			break
		}
	}
	// Remove port
	if idx := findByte(s, ':'); idx >= 0 {
		s = s[:idx]
	}
	// Remove trailing slash
	if len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// extractDomainFromBaseDN extracts domain from LDAP base DN
// e.g., "DC=example,DC=com" -> "example.com"
func extractDomainFromBaseDN(baseDN string) string {
	var parts []string
	for _, component := range splitString(baseDN, ",") {
		component = trimSpace(component)
		upper := toUpper(component)
		if len(upper) > 3 && upper[:3] == "DC=" {
			parts = append(parts, component[3:])
		}
	}
	return joinStrings(parts, ".")
}

// extractUsernameFromBindDN extracts the username from a bind DN
// e.g., "CN=administrator,CN=Users,DC=example,DC=com" -> "administrator"
func extractUsernameFromBindDN(bindDN string) string {
	for _, component := range splitString(bindDN, ",") {
		component = trimSpace(component)
		upper := toUpper(component)
		if len(upper) > 3 && upper[:3] == "CN=" {
			return component[3:]
		}
	}
	// Handle UPN format (user@domain.com) — strip the @domain part for SMB
	if atIdx := findByte(bindDN, '@'); atIdx >= 0 {
		return bindDN[:atIdx]
	}
	// If not a DN, return as-is (might be a plain username)
	return bindDN
}

// String helpers to avoid importing strings package just for these
func findByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func splitString(s, sep string) []string {
	var result []string
	for {
		i := indexOf(s, sep)
		if i < 0 {
			result = append(result, s)
			break
		}
		result = append(result, s[:i])
		s = s[i+len(sep):]
	}
	return result
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func toUpper(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		b[i] = c
	}
	return string(b)
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for _, p := range parts[1:] {
		result += sep + p
	}
	return result
}
