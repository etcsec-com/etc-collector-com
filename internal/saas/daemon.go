package saas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/etcsec-com/etc-collector/internal/api"
	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/discovery"
	"github.com/etcsec-com/etc-collector/internal/audit/exclusions"
	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/guitoken"
	"github.com/etcsec-com/etc-collector/internal/logger"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/internal/providers/azure"
	"github.com/etcsec-com/etc-collector/internal/providers/ldap"
	"github.com/etcsec-com/etc-collector/internal/providers/smb"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// submitLDAPConnectError extracts a *ldap.ConnectError from err (if present)
// and submits a structured result. Falls back to a generic LDAP_UNKNOWN_ERROR
// when classification fails. Always returns after submitting.
func (d *Daemon) submitLDAPConnectError(commandID, startedAt string, err error) {
	var ce *ldap.ConnectError
	if errors.As(err, &ce) {
		details := fmt.Sprintf("Resolution: %s\nDocs: docs/configuration/%s\nRaw: %v",
			ce.Resolution, ce.DocAnchor, ce.Raw)
		d.submitError(commandID, startedAt, ce.Code, ce.Message, details)
		return
	}
	d.submitError(commandID, startedAt, ldap.CodeUnknown, "LDAP connection failed", err.Error())
}

// Daemon manages the background SaaS agent
type Daemon struct {
	client    *Client
	credStore *CredentialStore
	creds     *Credentials
	manager   *providers.Manager
	engine    *audit.Engine
	logger    *logger.Logger
	version   string
	edition   string
	startTime time.Time
	lastCmd   time.Time
	lastError time.Time
	stopCh    chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	running   bool
	activeCmd string

	// Persisted dedup of executed command IDs. Survives daemon restarts so a
	// crash mid-exec doesn't re-trigger the same command on every boot (the
	// architectural cause of the v3.1.x crash-loops). Initialized in NewDaemon.
	cmdStore *commandStore

	// Component error tracking for enriched health reports
	componentErrors map[string]*ComponentError

	// Tracks when config was last updated from the local GUI (for SaaS sync)
	configUpdatedAt time.Time

	// Log file path for GET_LOGS command
	logFilePath string

	// Channel to reset the scheduled audit ticker
	scheduleResetCh chan int

	// LDAP override flags (CLI can override SaaS config)
	LDAPOverrides *LDAPOverrides

	// Azure/Entra local certificate override (CLI only — never cloud-managed; see
	// AzureOverrides doc)
	AzureOverrides *AzureOverrides

	// AllowInsecureGUIHTTP opts out of B_136's TLS requirement for a non-loopback
	// --gui-host: an explicit, operator-set escape hatch (--gui-allow-insecure-http)
	// rather than the tool silently deciding. Every request served this way is logged
	// loudly by StartEmbeddedGUI. Default false — see ResolveGUITLS.
	AllowInsecureGUIHTTP bool

	// Retry state for provider reconnection
	ldapRetryActive  bool
	azureRetryActive bool

	// Config directory for PID file and shutdown marker
	configDir string

	// Embedded GUI server (optional, started via StartEmbeddedGUI)
	embeddedGUI *api.Server

	// Command signing (K3, T_045). unsignedCommandsAccepted counts commands accepted
	// without a signature while at least one key IS installed — the fleet-migration
	// counter exposed on the health report. lastVerifiedKid is the most recent kid a
	// signature actually verified against, reported alongside it. Both mu-guarded.
	unsignedCommandsAccepted int
	lastVerifiedKid          string
}

// LDAPOverrides allows CLI flags to override SaaS-provided LDAP config
type LDAPOverrides struct {
	URL          string
	BindDN       string
	BindPassword string
	BaseDN       string
	TLSVerify    *bool // nil = use SaaS config
}

// AzureOverrides layers a LOCAL Entra client certificate on top of the SaaS-managed
// tenantId/clientId (B_026, T_048). Local-only by design, not cloud-pushed: unlike an
// LDAP bind password, an Entra app-only credential (secret or certificate) is only ever
// sent to Microsoft's fixed, non-attacker-influenceable token endpoint
// (login.microsoftonline.com) and is validated there against the specific
// (tenantId, clientId) pair — there is no rogue-host redirection vector for a
// resolveLDAPConfig-style guard (T_025/T_041) to close here, since a certificate's
// private key never leaves this process even in the cloud-pushed ClientSecret case
// that already exists. The simpler, equally safe choice is: the certificate travels
// over no channel this collector doesn't already trust with root/SYSTEM access — the
// local filesystem — and is never transmitted to or received from the SaaS at all.
// The cloud continues to own tenantId/clientId exactly as today; this only supplies
// the credential portion.
type AzureOverrides struct {
	ClientCertPath     string
	ClientCertPassword string
}

// NewDaemon creates a new daemon instance
func NewDaemon(configDir, version, edition string) (*Daemon, error) {
	credStore := NewCredentialStore(configDir)

	// Persisted command dedup lives under <dataDir>/state/. A failure here is
	// non-fatal — the daemon falls back to no dedup at all rather than refusing
	// to start (better to risk a re-run than to brick the host). An unresolvable data
	// dir now takes that same degraded path instead of silently writing state relative
	// to the working directory — see DefaultDataDir (A_004 K7(e)).
	var store *commandStore
	if dataDir, err := DefaultDataDir(); err != nil {
		logger.Global().Named("daemon").Warn("Failed to resolve data directory, dedup disabled", "error", err)
	} else {
		stateDir := filepath.Join(dataDir, "state")
		s, err := newCommandStore(stateDir)
		if err != nil {
			logger.Global().Named("daemon").Warn("Failed to init command store, dedup disabled", "error", err, "stateDir", stateDir)
		} else {
			store = s
		}
	}

	return &Daemon{
		configDir:       configDir,
		credStore:       credStore,
		logger:          logger.Global().Named("daemon"),
		version:         version,
		edition:         edition,
		stopCh:          make(chan struct{}),
		cmdStore:        store,
		componentErrors: make(map[string]*ComponentError),
		scheduleResetCh: make(chan int, 1),
	}, nil
}

// IsEnrolled returns true if the daemon is enrolled with SaaS
func (d *Daemon) IsEnrolled() bool {
	return d.credStore.Exists()
}

// Enroll enrolls this collector with the SaaS platform
func (d *Daemon) Enroll(ctx context.Context, token, saasURL string) error {
	client := NewClient(saasURL, "")

	hostname, _ := os.Hostname()

	req := EnrollRequest{
		EnrollmentToken:  token,
		CollectorVersion: d.version,
		CollectorEdition: d.edition,
		Hostname:         hostname,
		OsType:           runtime.GOOS,
		OsVersion:        getOSVersion(),
		Arch:             runtime.GOARCH,
		Capabilities:     []string{"ad", "sysvol", "azure"},
	}

	resp, err := client.Enroll(ctx, req)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	// Apply defaults for polling intervals
	if resp.Config.Polling.IntervalSeconds == 0 {
		resp.Config.Polling.IntervalSeconds = 86400 // 24h default for scheduled audits
	}
	if resp.Config.Polling.CommandIntervalSeconds == 0 {
		resp.Config.Polling.CommandIntervalSeconds = 30 // 30s default for command polling
	}
	if resp.Config.Polling.CommandTimeoutSeconds == 0 {
		resp.Config.Polling.CommandTimeoutSeconds = 600
	}

	// Store credentials
	creds := &Credentials{
		CollectorID:              resp.CollectorID,
		ApiKey:                   resp.ApiKey,
		SaaSURL:                  saasURL,
		Config:                   resp.Config,
		CommandSigningPublicKeys: resp.CommandSigningPublicKeys, // K3, T_045 — additive, absent on a pre-signing backend
	}

	if err := d.credStore.Save(creds); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}

	d.logger.Info("Enrollment successful",
		"collectorId", resp.CollectorID,
		"ldapConfigured", resp.Config.LDAP.IsConfigured(),
		"azureConfigured", resp.Config.Azure.IsConfigured(),
	)
	return nil
}

// UnenrollRemote notifies the SaaS backend (best-effort) and deletes local credentials
func (d *Daemon) UnenrollRemote(ctx context.Context) error {
	creds, err := d.credStore.Load()
	if err != nil || creds == nil {
		return d.credStore.Delete()
	}

	// Best-effort: notify backend
	client := NewClient(creds.SaaSURL, creds.ApiKey)
	if err := client.Unenroll(ctx, creds.CollectorID); err != nil {
		d.logger.Warn("Failed to notify SaaS backend of unenroll", "error", err)
	} else {
		d.logger.Info("SaaS backend notified of unenroll")
	}

	return d.credStore.Delete()
}

// LoadCredentials loads stored credentials
func (d *Daemon) LoadCredentials() (*Credentials, error) {
	return d.credStore.Load()
}

// CredStore returns the credential store
func (d *Daemon) CredStore() *CredentialStore {
	return d.credStore
}

// Start starts the daemon loops
func (d *Daemon) Start() error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("daemon already running")
	}
	d.mu.Unlock()

	// Load credentials
	creds, err := d.credStore.Load()
	if err != nil {
		return fmt.Errorf("load credentials: %w", err)
	}
	if creds == nil {
		return fmt.Errorf("not enrolled: run 'enroll' first")
	}
	d.creds = creds

	// Apply defaults for missing config fields (backwards compat with older credentials)
	if d.creds.Config.Polling.CommandIntervalSeconds <= 0 {
		d.creds.Config.Polling.CommandIntervalSeconds = 30
	}
	if d.creds.Config.Polling.CommandTimeoutSeconds <= 0 {
		d.creds.Config.Polling.CommandTimeoutSeconds = 600
	}

	// Create SaaS client
	d.client = NewClient(creds.SaaSURL, creds.ApiKey)

	// Crash recovery detection (before marking running)
	crashRecovered := d.detectCrashRecovery()
	d.removeCleanShutdown()
	if err := d.writePIDFile(); err != nil {
		d.logger.Warn("Failed to write PID file", "error", err)
	}

	// Mark running BEFORE provider init (polling-first architecture)
	d.mu.Lock()
	d.running = true
	d.startTime = time.Now()
	d.mu.Unlock()

	d.logger.Info("Starting daemon",
		"collectorId", creds.CollectorID,
		"saasUrl", creds.SaaSURL,
		"commandPollInterval", creds.Config.Polling.CommandIntervalSeconds,
		"auditScheduleInterval", creds.Config.Polling.IntervalSeconds,
	)

	// Warn if running from the legacy /usr/local/bin layout — UPDATE_COLLECTOR
	// will fail because the binary directory isn't in ReadWritePaths. The fix
	// is `sudo etc-collector install --upgrade`.
	d.warnIfLegacyLayout()

	// Start loops immediately: command polling + health reporting + scheduled audits
	// This ensures the daemon is always reachable by SaaS, even if providers fail
	d.wg.Add(3)
	go d.commandLoop()
	go d.healthLoop()
	go d.scheduledAuditLoop()

	// Report crash recovery after goroutines are started (so health report can be sent)
	if crashRecovered {
		d.logger.Warn("Previous daemon instance crashed. Recovered.")
		d.trackErrorWithCode("daemon", "CRASH_RECOVERY", "Recovered from unexpected shutdown")
		go d.sendHealthNow()
	}

	// Initialize providers (non-fatal — daemon continues regardless)
	// IsConfigured() checks for non-empty URL/TenantID, not just nil pointer.
	// This handles SaaS sending {"ldap": {}} or {"ldap": {"url": ""}} correctly.
	// IMPORTANT: wrapped in safeInit to recover from panics — a bad config
	// must NEVER prevent the daemon from polling for UPDATE_CONFIG commands.
	if !creds.Config.LDAP.IsConfigured() && !creds.Config.Azure.IsConfigured() {
		d.logger.Warn("No providers configured. Collector will start but cannot run audits until configured via UPDATE_CONFIG_AD or UPDATE_CONFIG_AZURE.")
	}

	if creds.Config.LDAP.IsConfigured() {
		if err := d.safeInit("ldap", func() error { return d.initLDAPProvider(creds.Config.LDAP) }); err != nil {
			d.logger.Error("LDAP init failed, starting background retry", "error", err)
			d.trackErrorWithCode("ldap", "LDAP_CONNECT_FAILED", fmt.Sprintf("init failed: %v", err))
			d.startProviderRetry("ldap")
		}
	} else {
		d.logger.Info("LDAP provider not configured (skipping)")
	}

	if creds.Config.Azure.IsConfigured() {
		if err := d.safeInit("azure", func() error { return d.initAzureProvider(creds.Config.Azure) }); err != nil {
			d.logger.Warn("Azure init failed, starting background retry", "error", err)
			d.trackErrorWithCode("azure", "AZURE_CONNECT_FAILED", fmt.Sprintf("init failed: %v", err))
			d.startProviderRetry("azure")
		}
	} else {
		d.logger.Info("Azure provider not configured (skipping)")
	}

	d.logger.Info("Daemon started", "engineReady", d.engine != nil)

	return nil
}

// safeInit runs a provider initialization function with panic recovery.
// A bad config must NEVER prevent the daemon from polling for commands.
func (d *Daemon) safeInit(name string, fn func() error) error {
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic during %s init: %v", name, r)
				d.logger.Error("PANIC in provider init (recovered)", "provider", name, "panic", fmt.Sprintf("%v", r))
			}
		}()
		err = fn()
	}()
	return err
}

// initLDAPProvider initializes the LDAP provider
func (d *Daemon) initLDAPProvider(ldapConfig *SaaSLDAPConfig) error {
	// Resolve LDAP config (CLI overrides > SaaS config). Refused merges return here
	// before any client is built — no bind, no SMB dial (A_004 K4).
	ldapCfg, err := d.resolveLDAPConfig(*ldapConfig)
	if err != nil {
		d.logger.Error("Refusing LDAP configuration", "error", err)
		return err
	}

	d.logger.Info("Connecting to LDAP",
		"url", ldapCfg.URL,
		"tlsVerify", ldapCfg.TLSVerify,
		"startTLS", ldapCfg.StartTLS,
		"tlsMinVersion", ldapCfg.TLSMinVersion,
		"hasCACert", ldapCfg.TLSCACert != "",
	)
	ldapClient, err := ldap.NewClient(buildLDAPClientConfig(ldapCfg))
	if err != nil {
		return fmt.Errorf("create LDAP client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := ldapClient.Connect(ctx); err != nil {
		return fmt.Errorf("connect to LDAP: %w", err)
	}
	d.logger.Info("LDAP connected")
	d.clearError("ldap")

	// Create provider manager and engine if not already created
	if d.manager == nil {
		d.manager = providers.NewManager()
	}
	if err := d.manager.Register(ldapClient); err != nil {
		// Provider may already be registered from a previous attempt; replace it
		if replaceErr := d.manager.Replace(ldapClient); replaceErr != nil {
			return fmt.Errorf("register/replace LDAP provider: %w", replaceErr)
		}
	}

	if d.engine == nil {
		d.engine = audit.NewEngine(nil, ldapClient)
	} else {
		d.engine.SetProvider(ldapClient)
	}
	d.syncEmbeddedGUI()

	// Try SMB/SYSVOL (optional). B_138 (T_081): smbServer must be an
	// authorized (DNS-SRV-published) domain controller for smbDomain — see
	// isAuthorizedSYSVOLTarget's doc comment.
	smbServer := extractServerFromLDAPURL(ldapCfg.URL)
	smbDomain := extractDomainFromDN(ldapCfg.BaseDN)
	smbUsername := extractUsername(ldapCfg.BindDN)
	if smbServer != "" {
		authCtx, authCancel := context.WithTimeout(context.Background(), 10*time.Second)
		authorized := isAuthorizedSYSVOLTarget(authCtx, smbServer, smbDomain)
		authCancel()
		if !authorized {
			d.logger.Warn("SMB/SYSVOL target is not a DNS-published domain controller for this domain, skipping",
				"server", smbServer, "domain", smbDomain)
		} else {
			smbClient := smb.NewClient(smb.Config{
				Server:   smbServer,
				Domain:   smbDomain,
				Username: smbUsername,
				Password: ldapCfg.BindPassword,
			})
			smbCtx, smbCancel := context.WithTimeout(context.Background(), 15*time.Second)
			if err := smbClient.Connect(smbCtx); err != nil {
				d.logger.Warn("SMB/SYSVOL connection failed, continuing without", "error", err)
			} else {
				d.logger.Info("SMB/SYSVOL connected")
				d.engine.SetSYSVOLProvider(smbClient)
			}
			smbCancel()
		}
	}

	return nil
}

// buildAzureConfig merges the SaaS-managed Entra tenantId/clientId (and, absent a
// local certificate override, clientSecret) with an operator-configured LOCAL
// certificate override (B_026, T_048). See AzureOverrides for why the certificate is
// local-only rather than cloud-pushed. A configured certificate wins over a configured
// secret — same precedence azure.newCredential already applies, kept consistent here
// so logging above this call reflects what will actually be used.
func buildAzureConfig(saasConfig *SaaSAzureConfig, overrides *AzureOverrides) azure.Config {
	cfg := azure.Config{}
	if saasConfig != nil {
		cfg.TenantID = saasConfig.TenantID
		cfg.ClientID = saasConfig.ClientID
		cfg.ClientSecret = saasConfig.ClientSecret
	}
	if overrides != nil {
		cfg.ClientCertPath = overrides.ClientCertPath
		cfg.ClientCertPassword = overrides.ClientCertPassword
	}
	return cfg
}

// initAzureProvider initializes the Azure provider
func (d *Daemon) initAzureProvider(azureConfig *SaaSAzureConfig) error {
	cfg := buildAzureConfig(azureConfig, d.AzureOverrides)
	d.logger.Info("Connecting to Azure",
		"tenantId", cfg.TenantID,
		"clientId", cfg.ClientID,
		"usingLocalCertificate", cfg.HasCertificate(),
	)

	// Create Azure client
	azureClient, err := azure.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("create Azure client: %w", err)
	}

	// Connect to Azure (authenticate and create Graph client)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := azureClient.Connect(ctx); err != nil {
		return fmt.Errorf("connect to Azure: %w", err)
	}
	d.logger.Info("Azure connected")
	d.clearError("azure")

	// Create provider manager if not already created
	if d.manager == nil {
		d.manager = providers.NewManager()
	}
	if err := d.manager.Register(azureClient); err != nil {
		// Provider may already be registered from a previous attempt; replace it
		if replaceErr := d.manager.Replace(azureClient); replaceErr != nil {
			return fmt.Errorf("register/replace Azure provider: %w", replaceErr)
		}
	}

	// Set or create engine with Azure provider
	if d.engine == nil {
		d.engine = audit.NewEngine(nil, azureClient)
	} else {
		d.engine.SetProvider(azureClient)
	}
	d.syncEmbeddedGUI()

	return nil
}

// Stop stops the daemon
func (d *Daemon) Stop() error {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return nil
	}
	d.running = false
	d.mu.Unlock()

	d.logger.Info("Stopping daemon")

	// Shutdown embedded GUI server first (before closing stopCh)
	if d.embeddedGUI != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := d.embeddedGUI.Shutdown(shutdownCtx); err != nil {
			d.logger.Warn("Embedded GUI shutdown error", "error", err)
		}
		cancel()
	}

	close(d.stopCh)
	d.wg.Wait()

	if d.manager != nil {
		d.manager.CloseAll()
	}

	// Write clean shutdown marker and remove PID file
	if err := d.writeCleanShutdown(); err != nil {
		d.logger.Warn("Failed to write clean shutdown marker", "error", err)
	}
	d.removePIDFile()

	return nil
}

// stopForExec signals background goroutines to exit without waiting for them.
// Intended for in-place exec (see update_inplace_unix.go:performBinarySwap):
// calling the regular Stop() from inside commandLoop would deadlock because
// Stop() calls wg.Wait() on a WaitGroup that counts commandLoop itself.
// syscall.Exec replaces the process image atomically — goroutines, FDs, and
// sockets are torn down by the kernel with the old image.
func (d *Daemon) stopForExec() {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	d.mu.Unlock()

	d.logger.Info("Signaling daemon goroutines before in-place exec")

	if d.embeddedGUI != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = d.embeddedGUI.Shutdown(shutdownCtx)
		cancel()
	}

	close(d.stopCh)
	// DO NOT wg.Wait() — we ARE one of the tracked goroutines (commandLoop).
	// DO NOT CloseAll providers / writeCleanShutdown / removePIDFile —
	// preExecCleanup already handled PID + shutdown marker, and syscall.Exec
	// will close connections via kernel teardown.
}

// trackErrorWithCode records a component error with a structured code for enriched health reports
func (d *Daemon) trackErrorWithCode(component, code, message string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ce, ok := d.componentErrors[component]; ok {
		ce.Count++
		ce.Message = message
		ce.Code = code
	} else {
		d.componentErrors[component] = &ComponentError{
			Component: component,
			Code:      code,
			Message:   message,
			Since:     time.Now().UTC().Format(time.RFC3339),
			Count:     1,
		}
	}
}

// trackError records a component error for enriched health reports
func (d *Daemon) trackError(component, message string) {
	d.trackErrorWithCode(component, "", message)
}

// clearError removes a component error (e.g. after successful reconnection)
func (d *Daemon) clearError(component string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.componentErrors, component)
}

// resolveAuthTokenLifetime resolves auth.tokenLifetime for the daemon's embedded GUI
// (B_047, T_048), read from <configDir>/config.yaml specifically — not viper's global
// search path, which can diverge from configDir under --config-dir — via the standard
// CLI flag > env > config.yaml > default precedence (internal/config/precedence.go).
//
// Scoped to Auth only: precedence.go is explicit that LDAP/Azure config must never
// reach the daemon's provider setup this way, only through SaaS commands and
// credentials.json — config.Load's full return value is used only to pull this one
// field, everything else in it is discarded.
func resolveAuthTokenLifetime(configDir string, fallback time.Duration) (time.Duration, error) {
	fileCfg, err := config.Load(filepath.Join(configDir, "config.yaml"))
	if err != nil {
		return fallback, err
	}
	return config.ResolveDuration(fallback, fileCfg.Auth.TokenLifetime), nil
}

// resolveServerTLSFromConfigFile reads server.tlsEnabled/tlsCertFile/tlsKeyFile from
// <configDir>/config.yaml specifically (B_136, T_060) — same reasoning as
// resolveAuthTokenLifetime: not viper's global search path, and scoped to Server.TLS*
// only, since LDAP/Azure config must never reach the daemon this way (precedence.go).
func resolveServerTLSFromConfigFile(configDir string) (enabled bool, certFile, keyFile string, err error) {
	fileCfg, err := config.Load(filepath.Join(configDir, "config.yaml"))
	if err != nil {
		return false, "", "", err
	}
	return fileCfg.Server.TLSEnabled, fileCfg.Server.TLSCertFile, fileCfg.Server.TLSKeyFile, nil
}

// StartEmbeddedGUI starts a local HTTP(S) server serving the admin GUI.
// This runs alongside the SaaS daemon loops, giving local access to the GUI.
// The GUI token hash is reloaded from disk on each request (hot-reload after gui-token reset).
//
// v3.1.22 — JWT keys are auto-generated under <configDir>/keys/ on first
// boot when missing. Without them, /api/v1/auth/token returned 500
// ("private key is required") and every subsequent API call was 401,
// silently breaking "Run Audit" in the GUI. Generating on demand keeps
// fresh installs zero-config: the daemon just works.
//
// Returns an error only when host is non-loopback and TLS could not be established at
// all (B_136, T_060) — see ResolveGUITLS. Every other failure in this function is
// logged and degrades gracefully rather than stopping the daemon, consistent with the
// rest of this method; TLS is the one case where starting anyway would mean silently
// serving the admin API in plaintext over the network.
func (d *Daemon) StartEmbeddedGUI(host string, port int) error {
	cfg := config.Default()
	cfg.Server.Host = host
	cfg.Server.Port = port
	cfg.Server.Environment = "production"

	// B_047 (T_048): auth.tokenLifetime must resolve via the same CLI flag > env >
	// config.yaml > default precedence (internal/config/precedence.go) as every other
	// setting — this daemon startup path was simply skipping it, always shipping
	// config.Default()'s hardcoded 30 days regardless of what the customer's
	// config.yaml said, on the mode this product is actually sold and defaults to.
	if lifetime, err := resolveAuthTokenLifetime(d.configDir, cfg.Auth.TokenLifetime); err != nil {
		d.logger.Warn("Failed to load config.yaml for auth settings, using default tokenLifetime", "error", err)
	} else {
		cfg.Auth.TokenLifetime = lifetime
	}

	// B_136 (T_060): same defect, same fix, for server.tlsEnabled/tlsCertFile/tlsKeyFile
	// — never read on this startup path, so a manually configured certificate in
	// config.yaml was silently ignored and the GUI always served plain HTTP regardless.
	fileTLSEnabled, fileTLSCert, fileTLSKey, tlsFileErr := resolveServerTLSFromConfigFile(d.configDir)
	if tlsFileErr != nil {
		d.logger.Warn("Failed to load config.yaml for TLS settings, treating TLS as unconfigured", "error", tlsFileErr)
	}

	// A non-loopback bind address requires TLS — ResolveGUITLS is the full arbitrage
	// (loopback vs. network, configured vs. auto-generated, existing-fleet impact). A
	// bootstrap self-signed certificate is generated on demand when needed, so an
	// already-installed collector doesn't lose GUI access on upgrade; only a genuine
	// failure to establish TLS at all (not an operator opt-out) stops startup.
	tlsEnabled, tlsCertFile, tlsKeyFile, autoGenerated, err := ResolveGUITLS(
		host, fileTLSEnabled, fileTLSCert, fileTLSKey,
		filepath.Join(d.configDir, "tls"), d.AllowInsecureGUIHTTP,
	)
	if err != nil {
		return fmt.Errorf("establish TLS for the admin GUI on %s:%d: %w (pass --gui-allow-insecure-http to run without TLS instead)", host, port, err)
	}
	cfg.Server.TLSEnabled = tlsEnabled
	cfg.Server.TLSCertFile = tlsCertFile
	cfg.Server.TLSKeyFile = tlsKeyFile
	switch {
	case autoGenerated:
		d.logger.Warn("Admin GUI is bound to a non-loopback interface with no certificate configured — generated a bootstrap self-signed one",
			"host", host, "port", port, "certFile", tlsCertFile)
	case !tlsEnabled && !IsLoopbackHost(host):
		d.logger.Warn("Admin GUI is serving PLAINTEXT HTTP on a network-reachable interface (--gui-allow-insecure-http) — the admin token travels unencrypted",
			"host", host, "port", port)
	}

	// JWT keypair lives next to the daemon's configDir so it survives
	// in-place upgrades (the WorkingDirectory is wiped on reinstall but
	// configDir is preserved per ReadWritePaths in the systemd unit).
	keysDir := filepath.Join(d.configDir, "keys")
	cfg.Auth.JWTPrivateKeyPath = filepath.Join(keysDir, "private.pem")
	cfg.Auth.JWTPublicKeyPath = filepath.Join(keysDir, "public.pem")
	if err := EnsureJWTKeys(keysDir); err != nil {
		d.logger.Error("Failed to ensure JWT keys for embedded GUI — token issuance will fail", "error", err)
	}
	if err := cfg.LoadKeys(); err != nil {
		d.logger.Error("Failed to load JWT keys for embedded GUI", "error", err)
	}

	// T_041/B_040: the admin API is now fail-closed when no gui-token hash exists (see
	// api.guiTokenMiddleware) — a collector upgraded rather than reinstalled before
	// gui-token existed would otherwise be locked out of its own admin API. Ensure a
	// hash exists before the server can accept a single request. Covers both the
	// foreground CLI path (cmd/etc-collector/saas.go) and the Windows service path
	// (daemon_windows.go), which both call this method directly.
	if _, token, generated, err := guitoken.EnsureHash(d.configDir); err != nil {
		d.logger.Error("Failed to ensure GUI access token — admin API will refuse all requests until 'gui-token reset' is run", "error", err)
	} else if generated {
		// B_135 (T_060): the token itself must never reach this logger — it also writes
		// to collector.log, which GET_LOGS can return over the SaaS channel. See
		// guitoken.AnnounceFirstRun for where the token actually goes.
		d.logger.Warn("No GUI access token was configured (upgraded install) — generated one now so the admin API stays protected. See stdout or <configDir>/gui-token.firstrun for the token.")
		if err := guitoken.AnnounceFirstRun(d.configDir, token); err != nil {
			d.logger.Error("Failed to write gui-token.firstrun", "error", err)
		}
		d.logger.Warn("To reset later: etc-collector gui-token reset")
	}

	srv := api.NewServer(cfg, d.manager)
	srv.SetVersionInfo(d.version, d.edition)
	srv.SetGuiTokenDir(d.configDir) // hot-reload gui-token.hash from disk on each request
	srv.SetConfigPath(filepath.Join(d.configDir, "config.yaml"))
	srv.SetOnConfigUpdate(d.handleGUIConfigUpdate)

	// Sync current engine if already initialized
	if d.engine != nil {
		srv.SetEngine(d.engine)
	}

	// Sync LDAP config from credentials so GUI shows provider status
	if d.creds != nil && d.creds.Config.LDAP.IsConfigured() {
		srv.SyncLDAPConfig(
			d.creds.Config.LDAP.URL,
			d.creds.Config.LDAP.BindDN,
			d.creds.Config.LDAP.BaseDN,
			d.creds.Config.LDAP.TLSVerify,
		)
	}

	d.embeddedGUI = srv

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.logger.Info("Starting embedded GUI", "host", host, "port", port, "tlsEnabled", cfg.Server.TLSEnabled)
		if err := srv.Start(); err != nil && err.Error() != "http: Server closed" {
			d.logger.Error("Embedded GUI stopped", "error", err)
		}
	}()
	return nil
}

// syncEmbeddedGUI updates the embedded GUI server's engine and config to match the daemon's
func (d *Daemon) syncEmbeddedGUI() {
	if d.embeddedGUI == nil {
		return
	}
	if d.engine != nil {
		d.embeddedGUI.SetEngine(d.engine)
	}
	if d.manager != nil {
		d.embeddedGUI.SetManager(d.manager)
	}
	if d.creds != nil && d.creds.Config.LDAP.IsConfigured() {
		d.embeddedGUI.SyncLDAPConfig(
			d.creds.Config.LDAP.URL,
			d.creds.Config.LDAP.BindDN,
			d.creds.Config.LDAP.BaseDN,
			d.creds.Config.LDAP.TLSVerify,
		)
	}
}

// handleGUIConfigUpdate is the callback invoked by the embedded GUI when config is updated.
// It persists to credentials.json, rebuilds the provider, and signals the SaaS.
func (d *Daemon) handleGUIConfigUpdate(provider string, params map[string]interface{}) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	switch provider {
	case "ldap":
		return d.handleGUIConfigUpdateLDAP(params)
	case "azure":
		return d.handleGUIConfigUpdateAzure(params)
	default:
		return fmt.Errorf("unknown provider: %s", provider)
	}
}

// mergeLDAPBindPassword decides which bind password a partial LDAP config update should
// carry. T_041/B_040: this merge composes a config from partial input the same way the
// admin API's resolveAdminBindPassword does, so it gets the same invariant — a stored
// password is only reused when the endpoint hasn't changed. Today the admin handlers
// already refuse to reach here with a mismatched (new URL, no password) pair, but that
// upstream guard is a fragile thing to rely on alone for a merge that composes a config
// from partial input; an explicit param password always wins regardless.
func mergeLDAPBindPassword(paramPassword, newURL, storedURL, storedPassword string) string {
	if paramPassword != "" {
		return paramPassword
	}
	if storedPassword != "" && newURL == storedURL {
		return storedPassword
	}
	return ""
}

func (d *Daemon) handleGUIConfigUpdateLDAP(params map[string]interface{}) error {
	// Check for deletion
	if del, _ := params["delete"].(bool); del {
		d.creds.Config.LDAP = &SaaSLDAPConfig{}
		if err := d.credStore.Save(d.creds); err != nil {
			return fmt.Errorf("persist config: %w", err)
		}
		d.logger.Info("LDAP config deleted from GUI")
		d.configUpdatedAt = time.Now()
		go d.sendHealthNow()
		return nil
	}

	// Build SaaS config from params
	newCfg := SaaSLDAPConfig{}
	if v, ok := params["url"].(string); ok {
		newCfg.URL = v
	}
	if v, ok := params["bindDN"].(string); ok {
		newCfg.BindDN = v
	}
	paramPassword, _ := params["bindPassword"].(string)
	var storedURL, storedPassword string
	if d.creds.Config.LDAP != nil {
		storedURL = d.creds.Config.LDAP.URL
		storedPassword = d.creds.Config.LDAP.BindPassword
	}
	newCfg.BindPassword = mergeLDAPBindPassword(paramPassword, newCfg.URL, storedURL, storedPassword)
	if v, ok := params["baseDN"].(string); ok {
		newCfg.BaseDN = v
	}
	if v, ok := params["tlsVerify"].(bool); ok {
		newCfg.TLSVerify = v
	}

	// Persist to credentials.json
	d.creds.Config.LDAP = &newCfg
	if err := d.credStore.Save(d.creds); err != nil {
		return fmt.Errorf("persist config: %w", err)
	}

	// Rebuild the LDAP provider (connection already tested by admin handler)
	d.logger.Info("LDAP config updated from GUI, rebuilding provider",
		"url", newCfg.URL, "baseDN", newCfg.BaseDN)

	d.configUpdatedAt = time.Now()

	// Sync embedded GUI with new config
	d.syncEmbeddedGUI()

	// Trigger immediate health report so SaaS sees the change
	go d.sendHealthNow()

	return nil
}

func (d *Daemon) handleGUIConfigUpdateAzure(params map[string]interface{}) error {
	// Check for deletion
	if del, _ := params["delete"].(bool); del {
		d.creds.Config.Azure = &SaaSAzureConfig{}
		if err := d.credStore.Save(d.creds); err != nil {
			return fmt.Errorf("persist config: %w", err)
		}
		d.logger.Info("Azure config deleted from GUI")
		d.configUpdatedAt = time.Now()
		go d.sendHealthNow()
		return nil
	}

	// Build SaaS config from params
	newCfg := SaaSAzureConfig{}
	if v, ok := params["tenantId"].(string); ok {
		newCfg.TenantID = v
	}
	if v, ok := params["clientId"].(string); ok {
		newCfg.ClientID = v
	}
	if v, ok := params["clientSecret"].(string); ok && v != "" {
		newCfg.ClientSecret = v
	} else if d.creds.Config.Azure != nil && d.creds.Config.Azure.ClientSecret != "" {
		newCfg.ClientSecret = d.creds.Config.Azure.ClientSecret
	}

	// Persist to credentials.json
	d.creds.Config.Azure = &newCfg
	if err := d.credStore.Save(d.creds); err != nil {
		return fmt.Errorf("persist config: %w", err)
	}

	d.logger.Info("Azure config updated from GUI, rebuilding provider",
		"tenantId", newCfg.TenantID)

	d.configUpdatedAt = time.Now()
	d.syncEmbeddedGUI()
	go d.sendHealthNow()

	return nil
}

// SetLogFile sets the log file path for the GET_LOGS command
func (d *Daemon) SetLogFile(path string) {
	d.logFilePath = path
}

// isLDAPConfigured returns true if LDAP credentials contain a real config (non-empty URL).
func (d *Daemon) isLDAPConfigured() bool {
	return d.creds != nil && d.creds.Config.LDAP.IsConfigured()
}

// isAzureConfigured returns true if Azure credentials contain a real config (non-empty tenant+client).
func (d *Daemon) isAzureConfigured() bool {
	return d.creds != nil && d.creds.Config.Azure.IsConfigured()
}

// --- PID file and crash recovery ---

func (d *Daemon) pidFilePath() string {
	return filepath.Join(d.configDir, "daemon.pid")
}

func (d *Daemon) cleanShutdownPath() string {
	return filepath.Join(d.configDir, ".clean_shutdown")
}

func (d *Daemon) writePIDFile() error {
	return os.WriteFile(d.pidFilePath(), []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
}

func (d *Daemon) removePIDFile() {
	os.Remove(d.pidFilePath())
}

func (d *Daemon) writeCleanShutdown() error {
	return os.WriteFile(d.cleanShutdownPath(), []byte(time.Now().UTC().Format(time.RFC3339)), 0644)
}

func (d *Daemon) removeCleanShutdown() {
	os.Remove(d.cleanShutdownPath())
}

// detectCrashRecovery checks if the previous daemon instance crashed.
// Returns true if: PID file exists with a dead process AND no clean shutdown marker.
func (d *Daemon) detectCrashRecovery() bool {
	pidData, err := os.ReadFile(d.pidFilePath())
	if err != nil {
		return false // No PID file = first run or already cleaned up
	}

	var oldPID int
	if _, err := fmt.Sscanf(string(pidData), "%d", &oldPID); err != nil {
		d.logger.Warn("Corrupt PID file found, treating as crash recovery")
		return true
	}

	if isProcessAlive(oldPID) {
		d.logger.Warn("Another daemon instance may be running", "pid", oldPID)
		return false
	}

	// Old process is dead. Check for clean shutdown marker.
	if _, err := os.Stat(d.cleanShutdownPath()); err == nil {
		return false // Clean shutdown marker exists
	}

	// PID file exists + process dead + no clean shutdown = crash
	d.logger.Warn("Crash recovery detected", "previousPID", oldPID)
	return true
}

// startProviderRetry launches a background goroutine that retries provider initialization
// with exponential backoff: 5s, 10s, 30s, 1min, 5min, capped at 15min.
func (d *Daemon) startProviderRetry(providerType string) {
	d.mu.Lock()
	switch providerType {
	case "ldap":
		if d.ldapRetryActive {
			d.mu.Unlock()
			return
		}
		d.ldapRetryActive = true
	case "azure":
		if d.azureRetryActive {
			d.mu.Unlock()
			return
		}
		d.azureRetryActive = true
	}
	d.mu.Unlock()

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer func() {
			d.mu.Lock()
			switch providerType {
			case "ldap":
				d.ldapRetryActive = false
			case "azure":
				d.azureRetryActive = false
			}
			d.mu.Unlock()
		}()

		backoffSteps := []time.Duration{
			5 * time.Second,
			10 * time.Second,
			30 * time.Second,
			1 * time.Minute,
			5 * time.Minute,
			15 * time.Minute,
		}
		step := 0

		for {
			delay := backoffSteps[step]
			if step < len(backoffSteps)-1 {
				step++
			}

			d.logger.Info("Provider reconnect scheduled",
				"provider", providerType,
				"retryIn", delay.String(),
				"attempt", step,
			)

			select {
			case <-d.stopCh:
				d.logger.Info("Provider retry cancelled (shutdown)", "provider", providerType)
				return
			case <-time.After(delay):
			}

			var err error
			switch providerType {
			case "ldap":
				if !d.isLDAPConfigured() {
					d.logger.Info("LDAP no longer configured, stopping retry")
					return
				}
				err = d.initLDAPProvider(d.creds.Config.LDAP)
			case "azure":
				if !d.isAzureConfigured() {
					d.logger.Info("Azure no longer configured, stopping retry")
					return
				}
				err = d.initAzureProvider(d.creds.Config.Azure)
			}

			if err == nil {
				d.logger.Info("Provider reconnected successfully", "provider", providerType)
				d.clearError(providerType)
				d.sendHealthNow()
				return
			}

			d.logger.Warn("Provider reconnect failed, will retry",
				"provider", providerType,
				"error", err,
				"nextRetryIn", backoffSteps[step].String(),
			)
			d.trackErrorWithCode(providerType,
				strings.ToUpper(providerType)+"_CONNECT_FAILED",
				fmt.Sprintf("reconnect failed: %v", err),
			)
		}
	}()
}

// commandLoop polls for commands and executes them
func (d *Daemon) commandLoop() {
	defer d.wg.Done()

	// Use CommandIntervalSeconds for frequent command polling (default 30s)
	// This is separate from IntervalSeconds which is the scheduled audit interval
	cmdInterval := d.creds.Config.Polling.CommandIntervalSeconds
	if cmdInterval <= 0 {
		cmdInterval = 30
	}
	interval := time.Duration(cmdInterval) * time.Second
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	d.logger.Info("Command polling started", "intervalSeconds", int(interval.Seconds()))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	d.pollAndExecute()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.pollAndExecute()
		}
	}
}

func (d *Daemon) pollAndExecute() {
	// Panic recovery to prevent goroutine death
	defer func() {
		if r := recover(); r != nil {
			d.logger.Error("PANIC in pollAndExecute (recovered)", "panic", fmt.Sprintf("%v", r))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	d.logger.Info("Polling for commands", "collectorId", d.creds.CollectorID)

	resp, err := d.client.PollCommands(ctx, d.creds.CollectorID)
	if err != nil {
		d.logger.Error("Poll commands FAILED", "error", err)
		return
	}

	d.logger.Info("Poll commands response", "commandCount", len(resp.Commands), "nextPollAt", resp.NextPollAt)

	// K3 (T_045) — backfill keys even on an empty poll; a key-only response with zero
	// commands is exactly what the migration plan expects for most polls.
	d.mergeCommandSigningKeys(resp.CommandSigningPublicKeys)

	if len(resp.Commands) == 0 {
		return
	}

	for _, cmd := range resp.Commands {
		select {
		case <-d.stopCh:
			return
		default:
			// Persisted dedup: skip commands the store already knows about.
			// "Knows about" includes Reserved-but-not-yet-Completed entries —
			// this is the crash-loop defense. If the daemon panicked during a
			// previous attempt at this exact command, the on-disk record stops
			// us from retrying it forever.
			if d.cmdStore != nil && d.cmdStore.Has(cmd.CommandID) {
				d.logger.Info("Skipping already-executed command", "commandId", cmd.CommandID, "type", cmd.Type)
				continue
			}

			// Reserve BEFORE exec so a crash mid-exec still leaves a marker.
			// A Reserve failure means we couldn't write to disk — log and run
			// the command anyway (degrading to no-dedup is better than freezing).
			if d.cmdStore != nil {
				if err := d.cmdStore.Reserve(cmd.CommandID, cmd.Type); err != nil {
					d.logger.Warn("Command store reserve failed (continuing without persisted dedup)",
						"commandId", cmd.CommandID, "error", err)
				}
			}

			d.logger.Info("Processing command", "commandId", cmd.CommandID, "type", cmd.Type, "createdAt", cmd.CreatedAt)
			d.executeCommand(cmd)

			// Mark complete. Status is informational — Has() already deduped
			// based on the Reserve. We don't have a clean exec result here so
			// "done" is the safest neutral label; submitSuccess/submitError
			// inside the command handlers tell the SaaS what really happened.
			if d.cmdStore != nil {
				if err := d.cmdStore.Complete(cmd.CommandID, "done"); err != nil {
					d.logger.Warn("Command store complete failed", "commandId", cmd.CommandID, "error", err)
				}
			}
		}
	}
}

// checkCommandExpiry returns nil only when raw is a parseable timestamp that has not
// yet passed at now. A missing or unparseable value is an error: we cannot prove the
// command is fresh, so the caller must refuse it rather than execute it.
//
// The cloud always populates expiresAt — createCommand computes it from a TTL
// (default 86400s, 3600s for UPDATE_COLLECTOR) and it is the single INSERT path into
// collector_commands — and serializes it as RFC3339 with milliseconds, which
// RFC3339Nano parses. Plain RFC3339 is accepted too.
func checkCommandExpiry(raw string, now time.Time) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return fmt.Errorf("missing expiresAt")
	}

	// RFC3339Nano first (handles fractional seconds like .079+00:00)
	expiresAt, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		expiresAt, err = time.Parse(time.RFC3339, s)
	}
	if err != nil {
		return fmt.Errorf("unparseable expiresAt %q", s)
	}

	if now.After(expiresAt) {
		return fmt.Errorf("command expired at %s", expiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

func (d *Daemon) executeCommand(cmd Command) {
	// Panic recovery to prevent goroutine death
	defer func() {
		if r := recover(); r != nil {
			d.logger.Error("PANIC in executeCommand (recovered)",
				"commandId", cmd.CommandID,
				"type", cmd.Type,
				"panic", fmt.Sprintf("%v", r),
			)
		}
	}()

	// Freshness check — fail CLOSED (A_004 K12). This used to skip the whole block
	// when ExpiresAt was empty and to ignore parse errors, so dropping or corrupting
	// one field disabled the only freshness control on every command, including
	// UPDATE_COLLECTOR. Now only an explicitly-parsed, not-yet-past timestamp runs.
	if err := checkCommandExpiry(cmd.ExpiresAt, time.Now().UTC()); err != nil {
		d.logger.Warn("Rejecting command (expiry check failed)",
			"commandId", cmd.CommandID, "type", cmd.Type, "expiresAt", cmd.ExpiresAt, "reason", err)
		return
	}

	// K3 (T_045) — verify before dispatch, same insertion point as checkCommandExpiry.
	// Phase 2: only a genuinely invalid signature (wrong kid, bad window, altered
	// payload, foreign collectorId) is rejected here; an absent key set or an unsigned
	// command with keys present are both accepted (see checkCommandSignature's doc).
	if err := d.checkCommandSignature(cmd); err != nil {
		d.logger.Warn("Rejecting command (signature check failed)",
			"commandId", cmd.CommandID, "type", cmd.Type, "reason", err)
		return
	}

	d.mu.Lock()
	d.activeCmd = cmd.Type
	d.lastCmd = time.Now()
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		d.activeCmd = ""
		d.mu.Unlock()
	}()

	d.logger.Info("Executing command", "commandId", cmd.CommandID, "type", cmd.Type)
	startedAt := time.Now().UTC().Format(time.RFC3339)

	switch cmd.Type {
	case CmdRunAuditAD:
		d.logger.Info("Dispatching RUN_AUDIT_AD", "commandId", cmd.CommandID, "params", fmt.Sprintf("%v", cmd.Parameters))
		d.executeAuditAD(cmd, startedAt)
	case CmdRunAuditAzure:
		d.logger.Info("Dispatching RUN_AUDIT_AZURE", "commandId", cmd.CommandID, "params", fmt.Sprintf("%v", cmd.Parameters))
		d.executeAuditAzure(cmd, startedAt)
	case CmdUpdateConfigAD:
		d.executeUpdateConfigAD(cmd, startedAt)
	case CmdUpdateConfigAzure:
		d.executeUpdateConfigAzure(cmd, startedAt)
	case CmdTestConnectionAD:
		d.executeTestConnectionAD(cmd, startedAt)
	case CmdDiscoverAD:
		d.executeDiscoverAD(cmd, startedAt)
	case CmdUpdateAssetFiltersAD:
		d.executeUpdateAssetFiltersAD(cmd, startedAt)
	case CmdTestConnectionAzure:
		d.executeTestConnectionAzure(cmd, startedAt)
	case CmdCheckPermissionsAzure:
		d.executeCheckPermissionsAzure(cmd, startedAt)
	case CmdHealthCheck:
		d.sendHealthNow()
		d.submitSuccess(cmd.CommandID, startedAt, nil)
	case CmdGetLogs:
		d.executeGetLogs(cmd, startedAt)
	case CmdUpdateCollector:
		d.executeUpdate(cmd, startedAt)
	case CmdRestart:
		d.submitSuccess(cmd.CommandID, startedAt, map[string]string{"note": "restart acknowledged"})
		d.logger.Info("Restart requested, stopping daemon for service manager restart")
		go func() {
			time.Sleep(time.Second)
			d.Stop()
			os.Exit(0) // Force process exit so Windows SCM marks service STOPPED and restarts it
		}()
	default:
		d.logger.Warn("Unknown command type", "commandId", cmd.CommandID, "type", cmd.Type)
		d.submitError(cmd.CommandID, startedAt, "UNKNOWN_COMMAND", fmt.Sprintf("unknown command type: %s", cmd.Type), "")
	}
}

// newRunOptions builds the RunOptions shared by both SaaS-driven audits. Both
// executeAuditAD and executeAuditAzure MUST go through it — see
// TestDaemonEnablesIPAnonymisation, which fails if a bare audit.RunOptions literal
// reappears in this file.
//
// A_004 K5 (RGPD) — AzureAnonymizeIP defaults to TRUE in daemon mode. AnonymizeSignInIPs
// (audit/engine.go, masks the last IPv4 octet) existed but was unreachable outside the
// CLI's --azure-anonymize-ip flag, so in SaaS mode employee sign-in IPs left the customer
// network in the clear. Daemon mode is exactly the mode where the data crosses that
// boundary, so on-by-default is the right side to err on.
//
// The cloud can still opt out per command with "azureAnonymizeIp": false — an explicit,
// logged, auditable action for a forensic investigation, rather than a silent default.
// (This is a privacy control against our own storage, not a defence against a hostile
// cloud: a cloud that wanted the IPs already receives the whole audit result.)
func (d *Daemon) newRunOptions(params map[string]interface{}, includeDetails bool, maxUsers, maxGroups int) audit.RunOptions {
	opts := audit.RunOptions{
		IncludeDetails:   includeDetails,
		MaxUsers:         maxUsers,
		MaxGroups:        maxGroups,
		Parallel:         true,
		AzureAnonymizeIP: true,
	}
	if v, ok := params["azureAnonymizeIp"]; ok {
		if b, ok := v.(bool); ok {
			opts.AzureAnonymizeIP = b
			if !b {
				d.logger.Warn("IP anonymisation DISABLED by SaaS command parameter — raw sign-in IPs will leave this network")
			}
		}
	}
	return opts
}

func (d *Daemon) executeAuditAD(cmd Command, startedAt string) {
	// Check if LDAP provider is configured
	if !d.isLDAPConfigured() {
		d.logger.Error("LDAP provider not configured", "commandId", cmd.CommandID)
		d.submitError(cmd.CommandID, startedAt, "PROVIDER_NOT_CONFIGURED", "LDAP provider not configured", "Run UPDATE_CONFIG_AD first to configure Active Directory credentials")
		return
	}

	if d.engine == nil {
		d.logger.Error("Audit engine is nil, cannot execute", "commandId", cmd.CommandID)
		d.submitError(cmd.CommandID, startedAt, "NO_ENGINE", "audit engine not initialized", "")
		return
	}

	// Check LDAP connectivity (configured but disconnected)
	if d.manager == nil || d.manager.Primary() == nil || !d.manager.Primary().IsConnected() {
		d.logger.Error("LDAP configured but not connected, cannot run audit", "commandId", cmd.CommandID)
		d.submitError(cmd.CommandID, startedAt, "LDAP_UNAVAILABLE",
			"Cannot run audit: LDAP connection is down",
			"The collector will automatically retry connecting. You can also send UPDATE_CONFIG_AD to trigger reconnection.")
		return
	}

	// Read parameters from command
	includeDetails := true // default
	if v, ok := cmd.Parameters["includeDetails"]; ok {
		if b, ok := v.(bool); ok {
			includeDetails = b
		}
	}

	var maxUsers, maxGroups int
	if v, ok := cmd.Parameters["maxUsers"]; ok {
		if f, ok := v.(float64); ok { // JSON numbers are float64
			maxUsers = int(f)
		}
	}
	if v, ok := cmd.Parameters["maxGroups"]; ok {
		if f, ok := v.(float64); ok {
			maxGroups = int(f)
		}
	}

	d.logger.Info("Starting audit execution",
		"commandId", cmd.CommandID,
		"includeDetails", includeDetails,
		"maxUsers", maxUsers,
		"maxGroups", maxGroups,
	)

	timeout := time.Duration(d.creds.Config.Polling.CommandTimeoutSeconds) * time.Second
	if timeout < 60*time.Second {
		timeout = 10 * time.Minute
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	opts := d.newRunOptions(cmd.Parameters, includeDetails, maxUsers, maxGroups)
	if v, ok := cmd.Parameters["networkProbes"]; ok {
		if b, ok := v.(bool); ok {
			opts.NetworkProbes = b
		}
	}
	scopeWarnings := applyScopeFromParams(cmd.Parameters, &opts, audit.DefaultRegistry)
	for _, w := range scopeWarnings {
		d.logger.Warn("scope warning", "commandId", cmd.CommandID, "warning", w)
	}

	// Asset filters: persisted in creds.Config.LDAP.AssetFilters via
	// UPDATE_ASSET_FILTERS_AD. Transient per-command override via cmd.Parameters["assetFilters"].
	if filterCfg, err := resolveAssetFilters(d.creds.Config.LDAP.AssetFilters, cmd.Parameters); err != nil {
		d.logger.Warn("Asset filters rejected — auditing without filters",
			"commandId", cmd.CommandID, "error", err)
	} else if filterCfg != nil {
		opts.Exclusions = filterCfg
		d.logger.Info("Asset filters applied",
			"commandId", cmd.CommandID, "rulesHash", filterCfg.Hash)
	}
	if v, ok := cmd.Parameters["exclusionsDryRun"]; ok {
		if b, ok := v.(bool); ok {
			opts.ExclusionsDryRun = b
		}
	}

	// CRITICAL FIX: Switch engine to LDAP provider before running audit
	// Bug: Without this, engine always uses the last configured provider (Azure)
	if ldapProvider, ok := d.manager.Get(providers.ProviderTypeLDAP); ok {
		d.engine.SetProvider(ldapProvider)
		d.logger.Info("Switched engine to LDAP provider", "commandId", cmd.CommandID)
	} else {
		d.logger.Error("LDAP provider not registered in manager", "commandId", cmd.CommandID)
		d.submitError(cmd.CommandID, startedAt, "PROVIDER_NOT_FOUND", "LDAP provider not found in manager", "")
		return
	}

	d.logger.Info("Calling engine.Run", "commandId", cmd.CommandID, "timeout", timeout.String())
	result, err := d.engine.Run(ctx, opts)
	if err != nil {
		d.logger.Error("Audit execution FAILED", "commandId", cmd.CommandID, "error", err)
		d.mu.Lock()
		d.lastError = time.Now()
		d.mu.Unlock()

		// Classify error for structured reporting
		errCode := "AUDIT_FAILED"
		errDetails := err.Error()
		errMsg := "Audit execution failed"
		if strings.Contains(errDetails, "connect") || strings.Contains(errDetails, "dial") {
			errCode = "AD_CONNECTION_FAILED"
			errMsg = "Failed to connect to LDAP server"
		} else if strings.Contains(errDetails, "bind") || strings.Contains(errDetails, "credential") {
			errCode = "LDAP_BIND_FAILED"
			errMsg = "LDAP bind failed"
		} else if strings.Contains(errDetails, "tls") || strings.Contains(errDetails, "x509") || strings.Contains(errDetails, "certificate") {
			errCode = "TLS_ERROR"
			errMsg = "TLS/SSL connection error"
		} else if ctx.Err() != nil {
			errCode = "AUDIT_TIMEOUT"
			errMsg = "Audit timed out"
		}
		d.trackError("audit_ad", errMsg)
		d.logger.Info("Submitting error result", "commandId", cmd.CommandID, "errorCode", errCode)
		d.submitError(cmd.CommandID, startedAt, errCode, errMsg, errDetails)
		return
	}

	d.clearError("audit_ad")

	// v3.1.31 hotfix — symmetric with Azure path: engine.Run swallows
	// ctx.Err() during detection so a deadline-cancelled audit returns
	// findings=0 with err=nil. Emit an explicit warning instead of
	// pretending success.
	if ctx.Err() == context.DeadlineExceeded {
		d.logger.Warn("AD audit context deadline exceeded — detection phase likely incomplete",
			"commandId", cmd.CommandID,
			"timeout", timeout.String(),
			"findingsCount", len(result.Findings),
			"score", result.Score,
		)
		result.Warnings = append(result.Warnings, types.Warning{
			Code:    "AUDIT_TIMEOUT",
			Message: fmt.Sprintf("AD audit timed out after %s — detection phase incomplete; findings count and score are NOT trustworthy", timeout),
		})
	} else {
		d.logger.Info("Audit engine completed successfully",
			"commandId", cmd.CommandID,
			"findings", len(result.Findings),
			"score", result.Score,
			"rating", result.Rating,
		)
	}

	ldapURL := d.creds.Config.LDAP.URL
	baseDN := d.creds.Config.LDAP.BaseDN
	tsResult := types.ConvertToTSFormat(result, "ad", ldapURL, baseDN, includeDetails)

	// Log the result size for debugging
	resultJSON, _ := json.Marshal(tsResult)
	d.logger.Info("Submitting audit result",
		"commandId", cmd.CommandID,
		"resultSizeBytes", len(resultJSON),
	)

	d.submitSuccess(cmd.CommandID, startedAt, tsResult)
}

func (d *Daemon) executeAuditAzure(cmd Command, startedAt string) {
	// Check if Azure provider is configured
	if !d.isAzureConfigured() {
		d.logger.Error("Azure provider not configured", "commandId", cmd.CommandID)
		d.submitError(cmd.CommandID, startedAt, "PROVIDER_NOT_CONFIGURED", "Azure provider not configured", "Run UPDATE_CONFIG_AZURE first to configure Azure credentials")
		return
	}

	if d.engine == nil {
		d.logger.Error("Audit engine is nil, cannot execute", "commandId", cmd.CommandID)
		d.submitError(cmd.CommandID, startedAt, "NO_ENGINE", "audit engine not initialized", "")
		return
	}

	// Check Azure connectivity (configured but disconnected)
	if azureProv, ok := d.manager.Get(providers.ProviderTypeAzure); !ok || !azureProv.IsConnected() {
		d.logger.Error("Azure configured but not connected, cannot run audit", "commandId", cmd.CommandID)
		d.submitError(cmd.CommandID, startedAt, "AZURE_UNAVAILABLE",
			"Cannot run audit: Azure connection is down",
			"The collector will automatically retry connecting. You can also send UPDATE_CONFIG_AZURE to trigger reconnection.")
		return
	}

	// Read parameters from command
	includeDetails := true // default
	if v, ok := cmd.Parameters["includeDetails"]; ok {
		if b, ok := v.(bool); ok {
			includeDetails = b
		}
	}

	var maxUsers, maxGroups int
	if v, ok := cmd.Parameters["maxUsers"]; ok {
		if f, ok := v.(float64); ok { // JSON numbers are float64
			maxUsers = int(f)
		}
	}
	if v, ok := cmd.Parameters["maxGroups"]; ok {
		if f, ok := v.(float64); ok {
			maxGroups = int(f)
		}
	}

	d.logger.Info("Starting Azure audit execution",
		"commandId", cmd.CommandID,
		"includeDetails", includeDetails,
		"maxUsers", maxUsers,
		"maxGroups", maxGroups,
	)

	timeout := time.Duration(d.creds.Config.Polling.CommandTimeoutSeconds) * time.Second
	// v3.1.31 — per-command override so the SaaS can dimension per tenant.
	if v, ok := cmd.Parameters["timeoutSeconds"]; ok {
		if f, ok := v.(float64); ok && f > 0 {
			timeout = time.Duration(f) * time.Second
		}
	}
	// v3.1.31 hotfix — Azure v3.1.30 enrichments (sign-in logs raw + audit
	// logs 90d + OAuth grants + PIM history + auth methods detail +
	// cross-tenant access) routinely push collection past 5 min on tenants
	// with >1k SPs. Floor to 15 min absorbs that comfortably; before this
	// fix the engine.Run context was cancelled mid-detection and the
	// daemon returned findings=0 / score=100 with no error or warning.
	if timeout < 15*time.Minute {
		timeout = 15 * time.Minute
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	opts := d.newRunOptions(cmd.Parameters, includeDetails, maxUsers, maxGroups)
	// v3.1.32 hotfix — sign-in logs collection runs in its own sub-context
	// inside the engine; allow the SaaS to dimension the budget per tenant
	// (high-volume tenants may want 600s; constrained tenants can keep 300s).
	if v, ok := cmd.Parameters["signInLogsMode"]; ok {
		if s, ok := v.(string); ok {
			opts.AzureSignInLogsMode = s
		}
	}
	if v, ok := cmd.Parameters["signInLogsBudgetSeconds"]; ok {
		if f, ok := v.(float64); ok && f > 0 {
			opts.AzureSignInLogsBudgetSeconds = int(f)
		}
	}
	// v3.1.36 — directory audits (90d, 5 security categories). Same per-tenant
	// dimensioning pattern: SaaS can override days/cap/budget without redeploy.
	if v, ok := cmd.Parameters["directoryAuditsDays"]; ok {
		if f, ok := v.(float64); ok && f > 0 {
			opts.AzureDirectoryAuditsDays = int(f)
		}
	}
	if v, ok := cmd.Parameters["directoryAuditsMax"]; ok {
		if f, ok := v.(float64); ok && f > 0 {
			opts.AzureDirectoryAuditsMax = int(f)
		}
	}
	if v, ok := cmd.Parameters["directoryAuditsBudgetSeconds"]; ok {
		if f, ok := v.(float64); ok && f > 0 {
			opts.AzureDirectoryAuditsBudgetSeconds = int(f)
		}
	}
	// v3.1.38 §2 — Hybrid edges (Entra ↔ AD). Sub-context budget on
	// /devices pagination so a 100k+ device tenant can't starve the rest.
	if v, ok := cmd.Parameters["hybridLinksBudgetSeconds"]; ok {
		if f, ok := v.(float64); ok && f > 0 {
			opts.AzureHybridLinksBudgetSeconds = int(f)
		}
	}
	if v, ok := cmd.Parameters["hybridLinksMax"]; ok {
		if f, ok := v.(float64); ok && f > 0 {
			opts.AzureHybridLinksMax = int(f)
		}
	}
	// v3.1.37 §1 — Embed binary version into audit.baselineSecurity for
	// auditor traceability (which baseline policy list applied).
	opts.CollectorVersion = d.version
	scopeWarnings := applyScopeFromParams(cmd.Parameters, &opts, audit.DefaultRegistry)
	for _, w := range scopeWarnings {
		d.logger.Warn("scope warning", "commandId", cmd.CommandID, "warning", w)
	}

	// CRITICAL FIX: Switch engine to Azure provider before running audit
	// Bug: Without this, if LDAP audit ran first, engine would use LDAP provider
	if azureProvider, ok := d.manager.Get(providers.ProviderTypeAzure); ok {
		d.engine.SetProvider(azureProvider)
		d.logger.Info("Switched engine to Azure provider", "commandId", cmd.CommandID)
	} else {
		d.logger.Error("Azure provider not registered in manager", "commandId", cmd.CommandID)
		d.submitError(cmd.CommandID, startedAt, "PROVIDER_NOT_FOUND", "Azure provider not found in manager", "")
		return
	}

	d.logger.Info("Calling engine.Run for Azure", "commandId", cmd.CommandID, "timeout", timeout.String())
	result, err := d.engine.Run(ctx, opts)
	if err != nil {
		d.logger.Error("Azure audit execution FAILED", "commandId", cmd.CommandID, "error", err)
		d.mu.Lock()
		d.lastError = time.Now()
		d.mu.Unlock()

		// Classify error for structured reporting
		errCode := "AUDIT_FAILED"
		errDetails := err.Error()
		errMsg := "Azure audit execution failed"
		if strings.Contains(errDetails, "authenticate") || strings.Contains(errDetails, "credential") {
			errCode = "AZURE_AUTH_FAILED"
			errMsg = "Azure authentication failed"
		} else if strings.Contains(errDetails, "tenant") {
			errCode = "AZURE_TENANT_ERROR"
			errMsg = "Azure tenant access error"
		} else if strings.Contains(errDetails, "permission") || strings.Contains(errDetails, "forbidden") || strings.Contains(errDetails, "insufficient") {
			errCode = "AZURE_PERMISSION_ERROR"
			errMsg = "Insufficient Azure permissions"
		} else if ctx.Err() != nil {
			errCode = "AUDIT_TIMEOUT"
			errMsg = "Audit timed out"
		}
		d.trackError("audit_azure", errMsg)
		d.logger.Info("Submitting error result", "commandId", cmd.CommandID, "errorCode", errCode)
		d.submitError(cmd.CommandID, startedAt, errCode, errMsg, errDetails)
		return
	}

	d.clearError("audit_azure")

	// v3.1.31 hotfix — engine.Run swallows ctx.Err() during the detection
	// phase (each detector that sees ctx cancelled returns 0 findings rather
	// than erroring) so a context-deadline timeout produces a "successful"
	// result with empty findings. Detect that here and emit an explicit
	// warning so the SaaS analyzer doesn't read the audit as a clean tenant.
	if ctx.Err() == context.DeadlineExceeded {
		d.logger.Warn("Azure audit context deadline exceeded — detection phase likely incomplete",
			"commandId", cmd.CommandID,
			"timeout", timeout.String(),
			"findingsCount", len(result.Findings),
			"score", result.Score,
		)
		result.Warnings = append(result.Warnings, types.Warning{
			Code:    "AUDIT_TIMEOUT",
			Message: fmt.Sprintf("Azure audit timed out after %s — detection phase incomplete; findings count and score are NOT trustworthy", timeout),
		})
	} else {
		d.logger.Info("Azure audit engine completed successfully",
			"commandId", cmd.CommandID,
			"findings", len(result.Findings),
			"score", result.Score,
			"rating", result.Rating,
		)
	}

	// For Azure, we don't have LDAP URL/BaseDN, pass tenant info instead
	tenantID := d.creds.Config.Azure.TenantID
	tsResult := types.ConvertToTSFormat(result, "azure", "", tenantID, includeDetails)

	// Log the result size for debugging
	resultJSON, _ := json.Marshal(tsResult)
	d.logger.Info("Submitting Azure audit result",
		"commandId", cmd.CommandID,
		"resultSizeBytes", len(resultJSON),
	)

	d.submitSuccess(cmd.CommandID, startedAt, tsResult)
}

// enrolledSaaSURL returns the SaaS origin stored at enrollment (credentials.json
// saasUrl), or "" when the collector is not enrolled.
func (d *Daemon) enrolledSaaSURL() string {
	if d.creds == nil {
		return ""
	}
	return d.creds.SaaSURL
}

func (d *Daemon) executeUpdate(cmd Command, startedAt string) {
	d.logger.Info("UPDATE_COLLECTOR received",
		"commandId", cmd.CommandID,
		"rawParams", fmt.Sprintf("%v", cmd.Parameters),
	)

	// The artifact must come from the SaaS host we enrolled with — see
	// validateDownloadURL. Empty (not enrolled) makes parseUpdateParams fail closed.
	params, err := parseUpdateParams(cmd.Parameters, d.enrolledSaaSURL())
	if err != nil {
		d.logger.Error("Invalid update parameters", "commandId", cmd.CommandID, "error", err)
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMS", "invalid update parameters", err.Error())
		return
	}

	d.logger.Info("Update parameters parsed",
		"commandId", cmd.CommandID,
		"targetVersion", params.targetVersion,
		"currentVersion", d.version,
		"downloadUrl", params.downloadURL,
		"checksumPrefix", params.checksum[:12]+"...",
	)

	// Skip if already at target version
	if params.targetVersion == d.version {
		d.logger.Info("Already at target version, skipping update", "version", d.version)
		d.submitSuccess(cmd.CommandID, startedAt, map[string]string{
			"note":    "already at target version",
			"version": d.version,
		})
		return
	}

	d.logger.Info("Starting collector update",
		"commandId", cmd.CommandID,
		"currentVersion", d.version,
		"targetVersion", params.targetVersion,
		"downloadUrl", params.downloadURL,
	)

	// Resolve binary path
	binaryPath, err := os.Executable()
	if err != nil {
		d.submitError(cmd.CommandID, startedAt, "UPDATE_FAILED", "cannot determine binary path", err.Error())
		return
	}
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		d.submitError(cmd.CommandID, startedAt, "UPDATE_FAILED", "cannot resolve binary path", err.Error())
		return
	}

	// Stage next to the current binary so os.Rename stays same-device.
	// Bug r-update-exdev-v3_1_5-B_01: with systemd ProtectSystem=strict +
	// ReadWritePaths listing configDir (/etc/etc-collector) AND dataDir
	// (/var/lib/etc-collector), each path is a distinct bind-mount in the
	// service's mount namespace. Renaming across them fails EXDEV even though
	// the physical filesystem is the same. Staging in filepath.Dir(binaryPath)
	// guarantees the rename target sits on the same mount as the source.
	stagingBase := filepath.Dir(binaryPath)

	// Stage the new binary (download + checksum + extract).
	staged, err := d.stageUpdateArtifact(params, stagingBase)
	if err != nil {
		d.logger.Error("Update staging failed", "commandId", cmd.CommandID, "error", err)
		d.submitError(cmd.CommandID, startedAt, "UPDATE_FAILED", "update staging failed", err.Error())
		return
	}

	// Hand off to the platform-specific swap. On Unix this performs an
	// in-place syscall.Exec (no fork, no exit). On Windows it launches a
	// detached watcher and signals the daemon to exit.
	d.performBinarySwap(cmd, startedAt, params, binaryPath, staged)
}

func (d *Daemon) submitSuccess(commandID, startedAt string, result interface{}) {
	// Use longer timeout for result submission (audit results can be large)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmdResult := CommandResult{
		CommandID:   commandID,
		Status:      "success",
		StartedAt:   startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339),
		Result:      result,
	}

	d.logger.Info("Submitting success result to SaaS", "commandId", commandID)
	if err := d.client.SubmitResult(ctx, d.creds.CollectorID, cmdResult); err != nil {
		d.logger.Error("FAILED to submit success result", "commandId", commandID, "error", err)
	} else {
		d.logger.Info("Success result submitted OK", "commandId", commandID)
	}
}

func (d *Daemon) submitError(commandID, startedAt, code, message, details string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	d.mu.Lock()
	d.lastError = time.Now()
	d.mu.Unlock()

	cmdResult := CommandResult{
		CommandID:   commandID,
		Status:      "error",
		StartedAt:   startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339),
		Error: &ResultError{
			Code:    code,
			Message: message,
			Details: details,
		},
	}

	d.logger.Info("Submitting error result to SaaS", "commandId", commandID, "errorCode", code)
	if err := d.client.SubmitResult(ctx, d.creds.CollectorID, cmdResult); err != nil {
		d.logger.Error("FAILED to submit error result", "commandId", commandID, "error", err)
	} else {
		d.logger.Info("Error result submitted OK", "commandId", commandID)
	}
}

func (d *Daemon) submitProgress(commandID, startedAt string, result interface{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmdResult := CommandResult{
		CommandID:   commandID,
		Status:      "received",
		StartedAt:   startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339),
		Result:      result,
	}

	d.logger.Info("Submitting progress to SaaS", "commandId", commandID)
	if err := d.client.SubmitResult(ctx, d.creds.CollectorID, cmdResult); err != nil {
		d.logger.Error("Failed to submit progress", "commandId", commandID, "error", err)
	}
}

func (d *Daemon) executeGetLogs(cmd Command, startedAt string) {
	if d.logFilePath == "" {
		d.submitError(cmd.CommandID, startedAt, "NO_LOG_FILE", "file logging not configured", "")
		return
	}

	// Parse line count from parameters (default 100, max 1000)
	lines := 100
	if v, ok := cmd.Parameters["lines"]; ok {
		if f, ok := v.(float64); ok && f > 0 {
			lines = int(f)
			if lines > 1000 {
				lines = 1000
			}
		}
	}

	content, err := readLastNLines(d.logFilePath, lines)
	if err != nil {
		d.submitError(cmd.CommandID, startedAt, "LOG_READ_FAILED",
			fmt.Sprintf("failed to read log file: %v", err), "")
		return
	}

	// B_135 (T_060): redact before this ever leaves the process — see log_redaction.go.
	// A log line written by an older binary version, before the write-time fix, can
	// still hold a plaintext token; this is the safety net for that, and for any
	// future logging mistake.
	content = redactKnownSecrets(content, d.knownSecretValues())

	d.submitSuccess(cmd.CommandID, startedAt, map[string]interface{}{
		"lines":   lines,
		"content": content,
	})
}

func readLastNLines(filePath string, n int) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	allLines := strings.Split(string(data), "\n")
	if len(allLines) > n {
		allLines = allLines[len(allLines)-n:]
	}
	return strings.Join(allLines, "\n"), nil
}

// healthLoop sends periodic health reports
func (d *Daemon) healthLoop() {
	defer d.wg.Done()

	// Health every 60 seconds
	interval := 60 * time.Second

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	d.sendHealthNow()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.sendHealthNow()
		}
	}
}

func (d *Daemon) sendHealthNow() {
	d.mu.Lock()
	ldapConnected := d.manager != nil && d.manager.Primary() != nil && d.manager.Primary().IsConnected()

	var lastCmdStr string
	if !d.lastCmd.IsZero() {
		lastCmdStr = d.lastCmd.UTC().Format(time.RFC3339)
	}

	var lastErrStr string
	if !d.lastError.IsZero() {
		lastErrStr = d.lastError.UTC().Format(time.RFC3339)
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	memMB := float64(memStats.Alloc) / 1024 / 1024

	// Build active providers list (ldap→"ad", + "sysvol" if SMB connected, + "azure" if configured)
	var activeProviders []string
	azureConnected := false
	if d.manager != nil {
		for _, pt := range d.manager.Types() {
			name := string(pt)
			if name == "ldap" {
				name = "ad"
			}
			if name == "azure" {
				azureConnected = true
			}
			activeProviders = append(activeProviders, name)
		}
	}
	if d.engine != nil && d.engine.HasSYSVOLProvider() {
		activeProviders = append(activeProviders, "sysvol")
	}

	// Collect component errors for enriched health report
	var compErrors []ComponentError
	for _, ce := range d.componentErrors {
		compErrors = append(compErrors, *ce)
	}

	// Determine status based on provider connectivity (not transient errors).
	// "degraded" = a configured provider is disconnected → SaaS shows "maintenance"
	// "unhealthy" is reserved for truly unrecoverable situations (never sent currently)
	// Component errors (audit failures, crash recovery) are informational — they
	// enrich the health report but do NOT downgrade status when connections are OK.
	status := "healthy"
	if !ldapConnected && d.isLDAPConfigured() {
		status = "degraded"
	}
	if !azureConnected && d.isAzureConfigured() {
		status = "degraded"
	}

	var configUpdatedStr string
	if !d.configUpdatedAt.IsZero() {
		configUpdatedStr = d.configUpdatedAt.UTC().Format(time.RFC3339)
	}

	health := HealthReport{
		Status:          status,
		Uptime:          time.Since(d.startTime).Seconds(),
		MemoryUsageMB:   memMB,
		LdapConnected:   ldapConnected,
		AzureConnected:  azureConnected,
		Version:         d.version,
		Edition:         d.edition,
		Providers:       activeProviders,
		LastCommandAt:   lastCmdStr,
		LastErrorAt:     lastErrStr,
		Errors:          compErrors,
		ConfigUpdatedAt: configUpdatedStr,
	}
	d.mu.Unlock()

	// K3 (T_045) — computed after unlocking: commandSigningStatus takes d.mu itself.
	health.CommandSigning = d.commandSigningStatus()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	healthResp, err := d.client.SendHealth(ctx, d.creds.CollectorID, health)
	if err != nil {
		d.logger.Warn("Health report failed", "error", err)
	} else {
		// Clear one-time crash recovery error after it has been reported
		d.clearError("daemon")
		if healthResp != nil {
			d.mergeCommandSigningKeys(healthResp.CommandSigningPublicKeys)
		}
	}
}

// scheduledAuditLoop runs audits at the configured IntervalSeconds
func (d *Daemon) scheduledAuditLoop() {
	defer d.wg.Done()

	intervalSec := d.creds.Config.Polling.IntervalSeconds
	if intervalSec <= 0 {
		intervalSec = 86400 // 24h default
	}
	interval := time.Duration(intervalSec) * time.Second

	d.logger.Info("Scheduled audit loop started", "intervalSeconds", intervalSec)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case newInterval := <-d.scheduleResetCh:
			ticker.Stop()
			if newInterval <= 0 {
				newInterval = 86400
			}
			interval = time.Duration(newInterval) * time.Second
			ticker = time.NewTicker(interval)
			d.logger.Info("Audit schedule reset", "newIntervalSeconds", newInterval)
		case <-ticker.C:
			d.runScheduledAudit()
		}
	}
}

// runScheduledAudit runs a scheduled AD audit if the engine is ready and no command is active
func (d *Daemon) runScheduledAudit() {
	d.mu.Lock()
	if d.activeCmd != "" {
		d.mu.Unlock()
		d.logger.Info("Skipping scheduled audit, command already active", "activeCmd", d.activeCmd)
		return
	}
	d.mu.Unlock()

	if d.engine == nil {
		d.logger.Warn("Skipping scheduled audit, engine not initialized")
		return
	}

	// Skip if LDAP is not connected (audit would fail anyway)
	if d.manager == nil || d.manager.Primary() == nil || !d.manager.Primary().IsConnected() {
		d.logger.Warn("Skipping scheduled audit: LDAP not connected")
		return
	}

	d.logger.Info("Running scheduled audit")

	// Run AD audit if LDAP configured
	if d.isLDAPConfigured() {
		cmd := Command{
			CommandID: fmt.Sprintf("scheduled-%d", time.Now().Unix()),
			Type:      CmdRunAuditAD,
			Parameters: map[string]interface{}{
				"includeDetails": true,
			},
		}
		startedAt := time.Now().UTC().Format(time.RFC3339)
		d.executeAuditAD(cmd, startedAt)
	}
}

// Status returns the current daemon status
func (d *Daemon) Status() *DaemonStatus {
	d.mu.Lock()
	defer d.mu.Unlock()

	return &DaemonStatus{
		Running:     d.running,
		Enrolled:    d.IsEnrolled(),
		Version:     d.version,
		Edition:     d.edition,
		Uptime:      time.Since(d.startTime),
		LastCommand: d.lastCmd,
		CurrentTask: d.activeCmd,
	}
}

// DaemonStatus represents the daemon's current state
type DaemonStatus struct {
	Running     bool          `json:"running"`
	Enrolled    bool          `json:"enrolled"`
	Version     string        `json:"version"`
	Edition     string        `json:"edition"`
	Uptime      time.Duration `json:"uptime"`
	LastCommand time.Time     `json:"lastCommand"`
	CurrentTask string        `json:"currentTask,omitempty"`
}

func (d *Daemon) executeUpdateConfigAD(cmd Command, startedAt string) {
	d.logger.Info("Processing UPDATE_CONFIG_AD", "commandId", cmd.CommandID)

	d.submitProgress(cmd.CommandID, startedAt, map[string]string{
		"provider": "ad",
		"note":     "command received, validating LDAP config...",
	})

	// Parse ldapUrl from parameters
	ldapURL, _ := cmd.Parameters["ldapUrl"].(string)

	// Parse ldap object from parameters
	ldapMap, ok := cmd.Parameters["ldap"].(map[string]interface{})
	if !ok || ldapMap == nil {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "missing or invalid 'ldap' object in parameters", "")
		return
	}

	// Build new SaaSLDAPConfig from parameters
	newSaaSCfg := SaaSLDAPConfig{
		URL: ldapURL,
	}
	if v, ok := ldapMap["baseDN"].(string); ok {
		newSaaSCfg.BaseDN = v
	}
	if v, ok := ldapMap["bindDN"].(string); ok {
		newSaaSCfg.BindDN = v
	}
	if v, ok := ldapMap["password"].(string); ok {
		newSaaSCfg.BindPassword = v
	}
	if v, ok := ldapMap["tlsVerify"].(bool); ok {
		newSaaSCfg.TLSVerify = v
	}
	if v, ok := ldapMap["caCertificate"].(string); ok && v != "" {
		newSaaSCfg.TLSCACert = v
	}

	// Build URL from host/port/protocol if ldapUrl not provided
	if newSaaSCfg.URL == "" {
		protocol, _ := ldapMap["protocol"].(string)
		host, _ := ldapMap["host"].(string)
		port, _ := ldapMap["port"].(float64) // JSON numbers are float64
		if host != "" {
			if protocol == "" {
				protocol = "ldaps"
			}
			if port == 0 {
				if protocol == "ldaps" {
					port = 636
				} else {
					port = 389
				}
			}
			newSaaSCfg.URL = fmt.Sprintf("%s://%s:%d", protocol, host, int(port))
		}
	}

	if newSaaSCfg.URL == "" {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "cannot determine LDAP URL from parameters", "")
		return
	}

	// Detect StartTLS: ldap:// on port 389 uses StartTLS
	if strings.HasPrefix(newSaaSCfg.URL, "ldap://") {
		newSaaSCfg.StartTLS = true
	}

	d.logger.Info("New LDAP config",
		"url", newSaaSCfg.URL,
		"baseDN", newSaaSCfg.BaseDN,
		"bindDN", newSaaSCfg.BindDN,
		"tlsVerify", newSaaSCfg.TLSVerify,
		"startTLS", newSaaSCfg.StartTLS,
	)

	// Apply CLI overrides (CLI flags always take precedence). A refused merge stops
	// here: no test bind, no SMB reconnection, and the config is NOT persisted (A_004 K4).
	resolvedCfg, err := d.resolveLDAPConfig(newSaaSCfg)
	if err != nil {
		d.logger.Error("Refusing SaaS-pushed LDAP configuration", "commandId", cmd.CommandID, "error", err)
		d.submitError(cmd.CommandID, startedAt, "LDAP_CONFIG_REFUSED", err.Error(), "")
		return
	}

	// Test connection with new credentials
	testClient, err := ldap.NewClient(buildLDAPClientConfig(resolvedCfg))
	if err != nil {
		d.submitError(cmd.CommandID, startedAt, "LDAP_CONFIG_INVALID", fmt.Sprintf("invalid LDAP config: %v", err), "")
		return
	}

	testCtx, testCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = testClient.Connect(testCtx)
	testCancel()
	if err != nil {
		d.submitLDAPConnectError(cmd.CommandID, startedAt, err)
		return
	}
	d.logger.Info("LDAP test connection successful with new credentials")
	d.clearError("ldap")

	// Create the permanent new client (reuse the test client that's already connected)
	newLdapClient := testClient

	// Replace LDAP provider in manager and engine
	if d.manager != nil {
		if err := d.manager.Replace(newLdapClient); err != nil {
			d.logger.Error("Failed to replace LDAP provider in manager", "error", err)
		}
	}
	if d.engine != nil {
		d.engine.SetProvider(newLdapClient)
	}
	d.syncEmbeddedGUI()

	// Try reconnecting SMB/SYSVOL with new credentials (optional, non-fatal).
	// B_138 (T_081): same DNS-SRV authorization as initLDAPProvider — this is
	// the direct cloud-command-driven path (UPDATE_CONFIG_AD), the one a
	// forged command would actually reach.
	if d.engine != nil {
		smbServer := extractServerFromLDAPURL(resolvedCfg.URL)
		smbDomain := extractDomainFromDN(resolvedCfg.BaseDN)
		smbUsername := extractUsername(resolvedCfg.BindDN)
		if smbServer != "" {
			authCtx, authCancel := context.WithTimeout(context.Background(), 10*time.Second)
			authorized := isAuthorizedSYSVOLTarget(authCtx, smbServer, smbDomain)
			authCancel()
			if !authorized {
				d.logger.Warn("SMB/SYSVOL target is not a DNS-published domain controller for this domain, skipping",
					"server", smbServer, "domain", smbDomain)
			} else {
				smbClient := smb.NewClient(smb.Config{
					Server:   smbServer,
					Domain:   smbDomain,
					Username: smbUsername,
					Password: resolvedCfg.BindPassword,
				})
				smbCtx, smbCancel := context.WithTimeout(context.Background(), 15*time.Second)
				if err := smbClient.Connect(smbCtx); err != nil {
					d.logger.Warn("SMB/SYSVOL reconnection failed with new config", "error", err)
				} else {
					d.logger.Info("SMB/SYSVOL reconnected with new config")
					d.engine.SetSYSVOLProvider(smbClient)
				}
				smbCancel()
			}
		}
	}

	// Persist new config to disk (save the SaaS config, not the resolved one with CLI overrides)
	d.creds.Config.LDAP = &newSaaSCfg
	if err := d.credStore.Save(d.creds); err != nil {
		d.logger.Error("Failed to persist updated config", "error", err)
		d.submitError(cmd.CommandID, startedAt, "CONFIG_SAVE_FAILED",
			fmt.Sprintf("Config applied in memory but failed to persist: %v", err), "")
		return
	}

	// Check if polling config is in the parameters — reset scheduler if intervalSeconds changed
	if v, ok := cmd.Parameters["polling"]; ok {
		if pollingMap, ok := v.(map[string]interface{}); ok {
			if intervalVal, ok := pollingMap["intervalSeconds"]; ok {
				if f, ok := intervalVal.(float64); ok && f > 0 {
					newInterval := int(f)
					d.creds.Config.Polling.IntervalSeconds = newInterval
					d.credStore.Save(d.creds) // Persist updated interval
					// Signal scheduler reset (non-blocking)
					select {
					case d.scheduleResetCh <- newInterval:
						d.logger.Info("Audit schedule updated", "intervalSeconds", newInterval)
					default:
					}
				}
			}
		}
	}

	// Collect TLS diagnostic info from the active connection
	diagCtx2, diagCancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	tlsDiag := newLdapClient.GetTLSDiag(diagCtx2)
	diagCancel2()

	d.logger.Info("UPDATE_CONFIG_AD applied successfully", "url", resolvedCfg.URL, "baseDN", resolvedCfg.BaseDN,
		"tlsActive", tlsDiag.TLSActive, "tlsVersion", tlsDiag.TLSVersion)
	d.submitSuccess(cmd.CommandID, startedAt, map[string]interface{}{
		"provider":         "ad",
		"configSaved":      true,
		"connectionTested": true,
		"connectionOK":     true,
		"url":              resolvedCfg.URL,
		"baseDN":           resolvedCfg.BaseDN,
		"bindDN":           resolvedCfg.BindDN,
		"ldapDiag":         tlsDiag,
	})
}

func (d *Daemon) executeUpdateConfigAzure(cmd Command, startedAt string) {
	d.logger.Info("Processing UPDATE_CONFIG_AZURE", "commandId", cmd.CommandID)

	d.submitProgress(cmd.CommandID, startedAt, map[string]string{
		"provider": "azure",
		"note":     "command received, validating Azure config...",
	})

	// Parse azure object from parameters
	azureMap, ok := cmd.Parameters["azure"].(map[string]interface{})
	if !ok || azureMap == nil {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "missing or invalid 'azure' object in parameters", "")
		return
	}

	// Build new SaaSAzureConfig from parameters
	newAzureCfg := SaaSAzureConfig{}
	if v, ok := azureMap["tenantId"].(string); ok && v != "" {
		newAzureCfg.TenantID = v
	} else {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "tenantId is required", "")
		return
	}
	if v, ok := azureMap["clientId"].(string); ok && v != "" {
		newAzureCfg.ClientID = v
	} else {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "clientId is required", "")
		return
	}
	if v, ok := azureMap["clientSecret"].(string); ok && v != "" {
		newAzureCfg.ClientSecret = v
	} else {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "clientSecret is required", "")
		return
	}

	d.logger.Info("New Azure config",
		"tenantId", newAzureCfg.TenantID,
		"clientId", newAzureCfg.ClientID,
	)

	// Test connection with new credentials
	testClient, err := azure.NewClient(azure.Config{
		TenantID:     newAzureCfg.TenantID,
		ClientID:     newAzureCfg.ClientID,
		ClientSecret: newAzureCfg.ClientSecret,
	})
	if err != nil {
		d.submitError(cmd.CommandID, startedAt, "AZURE_CONFIG_INVALID", fmt.Sprintf("invalid Azure config: %v", err), "")
		return
	}

	testCtx, testCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = testClient.Connect(testCtx)
	testCancel()
	if err != nil {
		d.submitError(cmd.CommandID, startedAt, "AZURE_CONNECTION_FAILED",
			fmt.Sprintf("Cannot connect to Azure tenant %s: %v", newAzureCfg.TenantID, err), "")
		return
	}
	d.logger.Info("Azure test connection successful with new credentials")
	d.clearError("azure")

	// Create the permanent new client (reuse the test client that's already connected)
	newAzureClient := testClient

	// Replace Azure provider in manager and engine
	if d.manager == nil {
		d.manager = providers.NewManager()
	}
	if err := d.manager.Register(newAzureClient); err != nil {
		d.logger.Warn("Failed to register Azure provider in manager (may already exist)", "error", err)
		// Try replacing instead
		if err := d.manager.Replace(newAzureClient); err != nil {
			d.logger.Error("Failed to replace Azure provider in manager", "error", err)
		}
	}

	// Set or create engine with Azure provider
	if d.engine == nil {
		d.engine = audit.NewEngine(nil, newAzureClient)
	} else {
		d.engine.SetProvider(newAzureClient)
	}
	d.syncEmbeddedGUI()

	// Persist new config to disk
	d.creds.Config.Azure = &newAzureCfg
	if err := d.credStore.Save(d.creds); err != nil {
		d.logger.Error("Failed to persist updated Azure config", "error", err)
		d.submitError(cmd.CommandID, startedAt, "CONFIG_SAVE_FAILED",
			fmt.Sprintf("Azure config applied in memory but failed to persist: %v", err), "")
		return
	}

	// Check permissions on the new config
	permCtx, permCancel := context.WithTimeout(context.Background(), 30*time.Second)
	checks := newAzureClient.CheckPermissions(permCtx)
	permCancel()

	var grantedPerms, missingPerms []string
	for _, c := range checks {
		if c.Granted {
			grantedPerms = append(grantedPerms, c.Permission)
		} else {
			missingPerms = append(missingPerms, c.Permission)
		}
	}

	d.logger.Info("UPDATE_CONFIG_AZURE applied successfully", "tenantId", newAzureCfg.TenantID,
		"permissionsGranted", len(grantedPerms), "permissionsMissing", len(missingPerms))
	d.submitSuccess(cmd.CommandID, startedAt, map[string]interface{}{
		"provider":         "azure",
		"configSaved":      true,
		"connectionTested": true,
		"connectionOK":     true,
		"tenantId":         newAzureCfg.TenantID,
		"clientId":         newAzureCfg.ClientID,
		"permissions": map[string]interface{}{
			"granted":      grantedPerms,
			"missing":      missingPerms,
			"total":        len(checks),
			"grantedCount": len(grantedPerms),
		},
	})
}

func (d *Daemon) executeTestConnectionAD(cmd Command, startedAt string) {
	d.logger.Info("Processing TEST_CONNECTION_AD", "commandId", cmd.CommandID)

	// Parse ldap object from parameters (same as UPDATE_CONFIG_AD)
	ldapMap, ok := cmd.Parameters["ldap"].(map[string]interface{})
	if !ok || ldapMap == nil {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "missing or invalid 'ldap' object in parameters", "")
		return
	}

	// Build SaaSLDAPConfig from parameters (reuse same parsing logic as UPDATE_CONFIG_AD)
	ldapURL, _ := cmd.Parameters["ldapUrl"].(string)
	newSaaSCfg := SaaSLDAPConfig{
		URL: ldapURL,
	}
	if v, ok := ldapMap["baseDN"].(string); ok {
		newSaaSCfg.BaseDN = v
	}
	if v, ok := ldapMap["bindDN"].(string); ok {
		newSaaSCfg.BindDN = v
	}
	if v, ok := ldapMap["password"].(string); ok {
		newSaaSCfg.BindPassword = v
	}
	if v, ok := ldapMap["tlsVerify"].(bool); ok {
		newSaaSCfg.TLSVerify = v
	}
	if v, ok := ldapMap["caCertificate"].(string); ok && v != "" {
		newSaaSCfg.TLSCACert = v
	}

	// Build URL from host/port/protocol if ldapUrl not provided
	if newSaaSCfg.URL == "" {
		protocol, _ := ldapMap["protocol"].(string)
		host, _ := ldapMap["host"].(string)
		port, _ := ldapMap["port"].(float64)
		if host != "" {
			if protocol == "" {
				protocol = "ldaps"
			}
			if port == 0 {
				if protocol == "ldaps" {
					port = 636
				} else {
					port = 389
				}
			}
			newSaaSCfg.URL = fmt.Sprintf("%s://%s:%d", protocol, host, int(port))
		}
	}

	if newSaaSCfg.URL == "" {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "cannot determine LDAP URL from parameters", "")
		return
	}

	// Detect StartTLS
	if strings.HasPrefix(newSaaSCfg.URL, "ldap://") {
		newSaaSCfg.StartTLS = true
	}

	d.logger.Info("Testing LDAP connection",
		"url", newSaaSCfg.URL,
		"baseDN", newSaaSCfg.BaseDN,
		"bindDN", newSaaSCfg.BindDN,
		"tlsVerify", newSaaSCfg.TLSVerify,
		"startTLS", newSaaSCfg.StartTLS,
	)

	// Test connection with new credentials (do NOT persist)
	testClient, err := ldap.NewClient(buildLDAPClientConfig(newSaaSCfg))
	if err != nil {
		d.submitError(cmd.CommandID, startedAt, "LDAP_CONFIG_INVALID", fmt.Sprintf("invalid LDAP config: %v", err), "")
		return
	}

	testCtx, testCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = testClient.Connect(testCtx)
	testCancel()
	if err != nil {
		d.submitLDAPConnectError(cmd.CommandID, startedAt, err)
		return
	}

	// Collect TLS diagnostic info
	diagCtx, diagCancel := context.WithTimeout(context.Background(), 10*time.Second)
	tlsDiag := testClient.GetTLSDiag(diagCtx)
	diagCancel()
	testClient.Close()

	d.logger.Info("LDAP test connection successful",
		"tlsActive", tlsDiag.TLSActive, "tlsVersion", tlsDiag.TLSVersion)
	d.submitSuccess(cmd.CommandID, startedAt, map[string]interface{}{
		"connected": true,
		"server":    extractServerFromLDAPURL(newSaaSCfg.URL),
		"baseDN":    newSaaSCfg.BaseDN,
		"ldapDiag":  tlsDiag,
	})
}

func (d *Daemon) executeTestConnectionAzure(cmd Command, startedAt string) {
	d.logger.Info("Processing TEST_CONNECTION_AZURE", "commandId", cmd.CommandID)

	// Parse azure object from parameters
	azureMap, ok := cmd.Parameters["azure"].(map[string]interface{})
	if !ok || azureMap == nil {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "missing or invalid 'azure' object in parameters", "")
		return
	}

	// Build SaaSAzureConfig from parameters
	testAzureCfg := SaaSAzureConfig{}
	if v, ok := azureMap["tenantId"].(string); ok && v != "" {
		testAzureCfg.TenantID = v
	} else {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "tenantId is required", "")
		return
	}
	if v, ok := azureMap["clientId"].(string); ok && v != "" {
		testAzureCfg.ClientID = v
	} else {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "clientId is required", "")
		return
	}
	if v, ok := azureMap["clientSecret"].(string); ok && v != "" {
		testAzureCfg.ClientSecret = v
	} else {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS", "clientSecret is required", "")
		return
	}

	d.logger.Info("Testing Azure connection", "tenantId", testAzureCfg.TenantID, "clientId", testAzureCfg.ClientID)

	// Test connection with new credentials (do NOT persist)
	testClient, err := azure.NewClient(azure.Config{
		TenantID:     testAzureCfg.TenantID,
		ClientID:     testAzureCfg.ClientID,
		ClientSecret: testAzureCfg.ClientSecret,
	})
	if err != nil {
		d.submitError(cmd.CommandID, startedAt, "AZURE_CONFIG_INVALID", fmt.Sprintf("invalid Azure config: %v", err), "")
		return
	}

	testCtx, testCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = testClient.Connect(testCtx)
	testCancel()
	if err != nil {
		d.submitError(cmd.CommandID, startedAt, "AZURE_CONNECTION_FAILED",
			fmt.Sprintf("Cannot connect to Azure tenant %s: %v", testAzureCfg.TenantID, err), "")
		return
	}

	// Try to fetch basic tenant info to verify permissions
	testCtx2, testCancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	tenantInfo, err := testClient.GetDomainInfo(testCtx2)
	testCancel2()

	var tenantName string
	if err == nil && tenantInfo != nil {
		tenantName = tenantInfo.DomainName
	}

	// Check permissions
	permCtx, permCancel := context.WithTimeout(context.Background(), 30*time.Second)
	checks := testClient.CheckPermissions(permCtx)
	permCancel()

	var grantedPerms, missingPerms []string
	for _, c := range checks {
		if c.Granted {
			grantedPerms = append(grantedPerms, c.Permission)
		} else {
			missingPerms = append(missingPerms, c.Permission)
		}
	}

	d.logger.Info("Azure test connection successful", "tenantName", tenantName,
		"permissionsGranted", len(grantedPerms), "permissionsMissing", len(missingPerms))
	d.submitSuccess(cmd.CommandID, startedAt, map[string]interface{}{
		"connected":  true,
		"tenantId":   testAzureCfg.TenantID,
		"tenantName": tenantName,
		"permissions": map[string]interface{}{
			"granted":      grantedPerms,
			"missing":      missingPerms,
			"total":        len(checks),
			"grantedCount": len(grantedPerms),
		},
	})
}

// resolveLDAPConfig merges SaaS config with CLI overrides.
//
// A_004 K4, scoped to the surface the security agent actually proved live (T_021
// VERDICTS.md §2-§3): the danger is not "the cloud can push LDAP config" — on the
// standard install path the cloud already holds the credential it pushes, so it steals
// nothing. The danger is the PARTIAL override: `daemon --ldap-bind-password <real secret>`
// WITHOUT `--ldap-url`. There the operator deliberately keeps the AD secret off the SaaS
// dashboard, and this function used to re-inject that secret on top of whatever URL the
// cloud supplied — proven live, the plaintext password reaching an attacker-chosen host
// via LDAP simple bind, followed by an SMB2/NTLM session-setup attempt to the same host.
//
// So: a locally-supplied credential is never used against a cloud-supplied endpoint.
// Pin the endpoint too (--ldap-url) or let the SaaS manage the credential.
//
// Returns an error rather than silently dropping the override — both callers refuse to
// connect, so no bind is ever attempted with the unsafe combination.
func (d *Daemon) resolveLDAPConfig(saasConfig SaaSLDAPConfig) (SaaSLDAPConfig, error) {
	cfg := saasConfig
	ov := d.LDAPOverrides

	localPassword := ov != nil && ov.BindPassword != ""
	localURL := ov != nil && ov.URL != ""

	if localPassword && !localURL {
		return SaaSLDAPConfig{}, fmt.Errorf(
			"refusing to use the locally-supplied --ldap-bind-password against the SaaS-supplied "+
				"LDAP endpoint %q: a credential held only on this host must not be sent to an endpoint "+
				"chosen remotely. Pin the endpoint with --ldap-url, or drop --ldap-bind-password and let "+
				"the SaaS manage the credential", saasConfig.URL)
	}

	if ov != nil {
		if ov.URL != "" {
			cfg.URL = ov.URL
		}
		if ov.BindDN != "" {
			cfg.BindDN = ov.BindDN
		}
		if ov.BindPassword != "" {
			cfg.BindPassword = ov.BindPassword
		}
		if ov.BaseDN != "" {
			cfg.BaseDN = ov.BaseDN
		}
	}

	// TLS verification. A local --ldap-tls-verify always wins. Otherwise a cloud-pushed
	// tlsVerify=false (or an omitted field, which decodes to the same false) must not
	// silently downgrade the transport:
	//   - with a local credential in play, the downgrade is refused outright — TLS
	//     verification is the last thing standing between that secret and a rogue host;
	//   - otherwise it is honoured but logged. Refusing it here would break customers
	//     legitimately running self-signed LDAPS — verified against the live fleet, where
	//     every UPDATE_CONFIG_AD on record pushes tlsVerify=false to an internal
	//     ldaps:// DC (see delivery).
	switch {
	case ov != nil && ov.TLSVerify != nil:
		cfg.TLSVerify = *ov.TLSVerify
	case !cfg.TLSVerify && localPassword:
		d.logger.Warn("Ignoring SaaS-pushed tlsVerify=false: a locally-supplied bind password is in use, "+
			"TLS verification stays ON. Pass --ldap-tls-verify=false to override deliberately.",
			"url", cfg.URL)
		cfg.TLSVerify = true
	case !cfg.TLSVerify:
		d.logger.Warn("LDAP TLS certificate verification is DISABLED by the SaaS-pushed config "+
			"(tlsVerify=false or omitted) — the LDAP connection is exposed to interception.",
			"url", cfg.URL)
	}

	return cfg, nil
}

func (d *Daemon) executeCheckPermissionsAzure(cmd Command, startedAt string) {
	d.logger.Info("Processing CHECK_PERMISSIONS_AZURE", "commandId", cmd.CommandID)

	if d.manager == nil {
		d.submitError(cmd.CommandID, startedAt, "NO_PROVIDER", "no Azure provider configured", "")
		return
	}
	azureProvider, ok := d.manager.Get(providers.ProviderTypeAzure)
	if !ok || azureProvider == nil {
		d.submitError(cmd.CommandID, startedAt, "NO_PROVIDER", "Azure provider not registered", "")
		return
	}
	azureClient, ok := azureProvider.(*azure.Client)
	if !ok {
		d.submitError(cmd.CommandID, startedAt, "INTERNAL_ERROR", "Azure provider type assertion failed", "")
		return
	}

	permCtx, permCancel := context.WithTimeout(context.Background(), 30*time.Second)
	checks := azureClient.CheckPermissions(permCtx)
	permCancel()

	var grantedPerms, missingPerms []string
	for _, c := range checks {
		if c.Granted {
			grantedPerms = append(grantedPerms, c.Permission)
		} else {
			missingPerms = append(missingPerms, c.Permission)
		}
	}

	d.logger.Info("CHECK_PERMISSIONS_AZURE completed",
		"granted", len(grantedPerms), "missing", len(missingPerms))
	d.submitSuccess(cmd.CommandID, startedAt, map[string]interface{}{
		"permissions": map[string]interface{}{
			"granted":      grantedPerms,
			"missing":      missingPerms,
			"total":        len(checks),
			"grantedCount": len(grantedPerms),
			"details":      checks,
		},
	})
}

// Helper functions

// buildLDAPClientConfig converts a SaaSLDAPConfig to an ldap.Config, routing
// inline PEM content to TLSCACertPEM and file paths to TLSCACert.
func buildLDAPClientConfig(cfg SaaSLDAPConfig) ldap.Config {
	c := ldap.Config{
		URL:           cfg.URL,
		BindDN:        cfg.BindDN,
		BindPassword:  cfg.BindPassword,
		BaseDN:        cfg.BaseDN,
		TLSVerify:     cfg.TLSVerify,
		TLSMinVersion: cfg.TLSMinVersion,
		StartTLS:      cfg.StartTLS,
		Timeout:       30 * time.Second,
	}
	if strings.HasPrefix(strings.TrimSpace(cfg.TLSCACert), "-----BEGIN") {
		c.TLSCACertPEM = cfg.TLSCACert
	} else {
		c.TLSCACert = cfg.TLSCACert
	}
	return c
}

func extractServerFromLDAPURL(ldapURL string) string {
	s := ldapURL
	for _, prefix := range []string{"ldaps://", "ldap://", "LDAPS://", "LDAP://"} {
		if len(s) > len(prefix) && s[:len(prefix)] == prefix {
			s = s[len(prefix):]
			break
		}
	}
	if idx := strings.IndexByte(s, ':'); idx >= 0 {
		s = s[:idx]
	}
	if len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func extractDomainFromDN(baseDN string) string {
	var parts []string
	for _, component := range strings.Split(baseDN, ",") {
		component = strings.TrimSpace(component)
		if strings.HasPrefix(strings.ToUpper(component), "DC=") {
			parts = append(parts, component[3:])
		}
	}
	return strings.Join(parts, ".")
}

func extractUsername(bindDN string) string {
	for _, component := range strings.Split(bindDN, ",") {
		component = strings.TrimSpace(component)
		if strings.HasPrefix(strings.ToUpper(component), "CN=") {
			return component[3:]
		}
	}
	if idx := strings.IndexByte(bindDN, '@'); idx >= 0 {
		return bindDN[:idx]
	}
	return bindDN
}

// sysvolLookupSRV and sysvolLookupIPAddr are the DNS calls
// isAuthorizedSYSVOLTarget uses, as package vars so tests can substitute
// canned records instead of hitting real DNS.
var (
	sysvolLookupSRV    = net.DefaultResolver.LookupSRV
	sysvolLookupIPAddr = net.DefaultResolver.LookupIPAddr
)

// isAuthorizedSYSVOLTarget reports whether host is a DNS-SRV-published domain
// controller for domain.
//
// B_138 (T_081): the SYSVOL/GPO read below (SetSYSVOLProvider) is a real,
// legitimate feature — detectors read Group Policy from it as part of
// auditing the same domain this collector is already bound to via LDAP. But
// the host it dialed was extractServerFromLDAPURL(cloud-suppliedURL) with no
// independent check at all: a forged or malicious UPDATE_CONFIG_AD (this
// channel isn't cryptographically verified — see B_141/K3) could point a
// root/SYSTEM process on a customer DC at an SMB target of the sender's
// choosing and have it complete an NTLM handshake there, on demand — a
// coercion/relay primitive regardless of which credentials happen to be in
// play. This collector always runs ON a domain controller for the domain it
// audits (the product's own deployment model), which always has that
// domain's own _ldap._tcp SRV records resolvable locally — so requiring the
// SMB target to be one of those DNS-vouched-for controllers, instead of
// trusting a bare string echoed back from whatever last called
// UPDATE_CONFIG_AD, raises the bar from "one forged command" to "control the
// domain's own DNS". Fails closed (false) on any lookup error or empty
// record set, same posture as K12's replay-window fix elsewhere in this
// ticket — SYSVOL access is skipped, not silently granted, when it can't be
// verified.
func isAuthorizedSYSVOLTarget(ctx context.Context, host, domain string) bool {
	if host == "" || domain == "" {
		return false
	}
	_, srvs, err := sysvolLookupSRV(ctx, "ldap", "tcp", domain)
	if err != nil || len(srvs) == 0 {
		return false
	}

	normalizedHost := strings.TrimSuffix(strings.ToLower(host), ".")
	hostIP := net.ParseIP(host)

	for _, srv := range srvs {
		target := strings.TrimSuffix(strings.ToLower(srv.Target), ".")
		if target == normalizedHost {
			return true
		}
		if hostIP == nil {
			continue
		}
		addrs, err := sysvolLookupIPAddr(ctx, srv.Target)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr.IP.Equal(hostIP) {
				return true
			}
		}
	}
	return false
}

func getOSVersion() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// resolveAssetFilters chooses the effective asset filter config for an audit.
// Precedence: cmd.Parameters["assetFilters"] (per-command override) >
// persisted creds.Config.LDAP.AssetFilters. Returns nil if neither is set.
// Validation errors are returned so the caller can log and continue without
// filters rather than aborting the audit silently.
func resolveAssetFilters(persisted map[string]interface{}, params map[string]interface{}) (*exclusions.Config, error) {
	if params != nil {
		if override, ok := params["assetFilters"].(map[string]interface{}); ok && len(override) > 0 {
			return exclusions.LoadFromMap(override)
		}
	}
	if len(persisted) > 0 {
		return exclusions.LoadFromMap(persisted)
	}
	return nil, nil
}

// executeDiscoverAD runs asset discovery against the current LDAP provider and
// submits the manifest as the command result. No detectors are run.
func (d *Daemon) executeDiscoverAD(cmd Command, startedAt string) {
	if !d.isLDAPConfigured() {
		d.submitError(cmd.CommandID, startedAt, "LDAP_NOT_CONFIGURED",
			"LDAP provider not configured", "")
		return
	}

	// Sample size: per-command override > default 50.
	sampleSize := 50
	if v, ok := cmd.Parameters["sampleSize"]; ok {
		switch n := v.(type) {
		case int:
			sampleSize = n
		case float64:
			sampleSize = int(n)
		}
	}
	// Full listing: return every asset (not just a capped sample). Enables
	// per-user checkbox UIs in the SaaS config page.
	fullListing := false
	if v, ok := cmd.Parameters["fullListing"].(bool); ok {
		fullListing = v
	}
	// IncludeGroupMembers: override the default "match fullListing" behaviour
	// so the SaaS can opt out of the extra members[] payload on very large
	// domains. Nil → daemon lets discovery.Run decide from fullListing.
	var includeGroupMembers *bool
	if v, ok := cmd.Parameters["includeGroupMembers"].(bool); ok {
		includeGroupMembers = &v
	}

	// Longer timeout for full listing — 100k users can take a minute or two.
	timeout := 5 * time.Minute
	if fullListing {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	provider, ok := d.manager.Get(providers.ProviderTypeLDAP)
	if !ok {
		d.submitError(cmd.CommandID, startedAt, "PROVIDER_NOT_FOUND",
			"LDAP provider not registered", "")
		return
	}
	ldapLike, ok := provider.(discovery.LDAPLike)
	if !ok {
		d.submitError(cmd.CommandID, startedAt, "PROVIDER_UNSUPPORTED",
			"LDAP provider does not expose discovery methods", "")
		return
	}

	d.logger.Info("Running DISCOVER_AD",
		"commandId", cmd.CommandID,
		"sampleSize", sampleSize,
		"fullListing", fullListing,
	)

	// Throttle progress submissions to avoid spamming the SaaS (one POST
	// per phase transition is enough; minimum 500ms gap between submits).
	var lastProgressAt time.Time
	progressFn := func(evt discovery.ProgressEvent) {
		if time.Since(lastProgressAt) < 500*time.Millisecond && evt.Phase != "done" {
			return
		}
		lastProgressAt = time.Now()
		d.submitProgress(cmd.CommandID, startedAt, map[string]interface{}{
			"discoveryProgress": evt,
		})
	}

	manifest, err := discovery.Run(ctx, ldapLike, discovery.Options{
		SampleSize:          sampleSize,
		FullListing:         fullListing,
		IncludeGroupMembers: includeGroupMembers,
		Progress:            progressFn,
	})
	if err != nil {
		d.logger.Error("Discovery failed", "commandId", cmd.CommandID, "error", err)
		d.submitLDAPConnectError(cmd.CommandID, startedAt, err)
		return
	}

	d.logger.Info("Discovery completed",
		"commandId", cmd.CommandID,
		"users", manifest.Counts.Users,
		"computers", manifest.Counts.Computers,
		"groups", manifest.Counts.Groups,
		"ous", manifest.Counts.OUs,
	)
	d.submitSuccess(cmd.CommandID, startedAt, map[string]interface{}{"discovery": manifest})
}

// executeUpdateAssetFiltersAD validates a pushed exclusions config and
// persists it in credentials.json. Subsequent audits pick it up automatically.
func (d *Daemon) executeUpdateAssetFiltersAD(cmd Command, startedAt string) {
	raw, ok := cmd.Parameters["assetFilters"].(map[string]interface{})
	if !ok {
		d.submitError(cmd.CommandID, startedAt, "INVALID_PARAMETERS",
			"assetFilters must be an object", "")
		return
	}

	// Empty map clears the config.
	if len(raw) == 0 {
		d.mu.Lock()
		d.creds.Config.LDAP.AssetFilters = nil
		if err := d.credStore.Save(d.creds); err != nil {
			d.mu.Unlock()
			d.submitError(cmd.CommandID, startedAt, "PERSIST_FAILED",
				"failed to persist credentials", err.Error())
			return
		}
		d.mu.Unlock()
		d.submitSuccess(cmd.CommandID, startedAt, map[string]interface{}{
			"note":      "asset filters cleared",
			"rulesHash": "",
		})
		go d.sendHealthNow()
		return
	}

	cfg, err := exclusions.LoadFromMap(raw)
	if err != nil {
		d.submitError(cmd.CommandID, startedAt, "INVALID_ASSET_FILTERS",
			"asset filters config rejected", err.Error())
		return
	}

	d.mu.Lock()
	d.creds.Config.LDAP.AssetFilters = raw
	if err := d.credStore.Save(d.creds); err != nil {
		d.mu.Unlock()
		d.submitError(cmd.CommandID, startedAt, "PERSIST_FAILED",
			"failed to persist credentials", err.Error())
		return
	}
	d.mu.Unlock()

	d.logger.Info("Asset filters updated", "commandId", cmd.CommandID, "rulesHash", cfg.Hash)
	d.submitSuccess(cmd.CommandID, startedAt, map[string]interface{}{
		"note":      "asset filters updated",
		"rulesHash": cfg.Hash,
	})
	go d.sendHealthNow()
}
