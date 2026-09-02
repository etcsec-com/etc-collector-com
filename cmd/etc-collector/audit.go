package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/exclusions"
	"github.com/etcsec-com/etc-collector/internal/config"
	"github.com/etcsec-com/etc-collector/internal/providers"
	"github.com/etcsec-com/etc-collector/internal/providers/azure"
	"github.com/etcsec-com/etc-collector/internal/providers/ldap"
	"github.com/etcsec-com/etc-collector/internal/providers/smb"
	"github.com/etcsec-com/etc-collector/internal/saas"
	"github.com/etcsec-com/etc-collector/pkg/types"
	"github.com/spf13/cobra"

	// Import detectors to register them via init()
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/ad"
	_ "github.com/etcsec-com/etc-collector/internal/audit/detectors/azure"
)

// Common audit flags
var (
	auditOutput         string
	auditFormat         string
	auditIncludeDetails bool
	auditNetworkProbes  bool
	// auditAsOf — B_175 (T_067). RFC3339; see resolveAuditAsOf and
	// audit.RunOptions.AsOf's doc comment (internal/audit/engine.go) for why this
	// exists: replaying a frozen bench against the real wall clock makes recency
	// detectors diverge simply because time passed between two replays of the
	// identical capture. Empty (the default) means "the real moment this audit
	// runs" — exactly today's behavior, unchanged.
	auditAsOf string
)

// AD-specific flags
var (
	auditLDAPURL           string
	auditLDAPBindDN        string
	auditLDAPBindPass      string
	auditLDAPBaseDN        string
	auditLDAPTLSVerify     bool
	auditLDAPCACert        string
	auditLDAPTLSMinVersion string
	auditLDAPStartTLS      bool
)

// Asset-filter flags (shared by all audit subcommands, applied to AD only for v1)
var (
	auditExclusionsPath   string
	auditExclusionsDryRun bool
)

// Scope flags (shared by all audit sub-commands).
var (
	scopeProfile           string
	scopeIncludeCategories []string
	scopeExcludeCategories []string
	scopeIncludeDetectors  []string
	scopeExcludeDetectors  []string
)

// Azure-specific flags
var (
	auditAzureTenantID     string
	auditAzureClientID     string
	auditAzureClientSecret string
	// Certificate auth (client_assertion) — the alternative to a client
	// secret for tenants that forbid secret creation.
	auditAzureClientCert     string
	auditAzureClientCertPass string
	auditAzureInclude        []string
	auditAzureSkipPermCheck  bool
	// v3.1.30 §1 — sign-in logs deep collection (raw is the default, see
	// engine RunOptions docstring for why aggregating kills the SOC use cases).
	auditAzureSignInLogsMode   string
	auditAzureSignInLogsDays   int
	auditAzureSignInLogsMax    int
	auditAzureSignInLogsBudget int
	auditAzureAnonymizeIP      bool
	auditGzipOutput            bool

	// v3.1.36 — directory audits (90d, 5 security categories)
	auditAzureDirectoryAuditsDays   int
	auditAzureDirectoryAuditsMax    int
	auditAzureDirectoryAuditsBudget int

	// v3.1.38 §2 — hybrid edges (Entra ↔ AD)
	auditAzureHybridLinksMax    int
	auditAzureHybridLinksBudget int
)

// Google-specific flags
var (
	auditGoogleKeyFile    string
	auditGoogleDomain     string
	auditGoogleAdminEmail string
)

// auditCmd is the parent command for all audit subcommands
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a one-shot security audit",
	Long: `Run a security audit against an identity provider and output results as JSON.

No server required — connect, audit, output, exit.

Examples:
  etc-collector audit ad --ldap-url ldaps://dc:636 --ldap-bind-dn CN=admin,CN=Users,DC=example,DC=com --ldap-bind-password secret --ldap-base-dn DC=example,DC=com -o result.json
  etc-collector audit azure --tenant-id xxx --client-id xxx --client-secret xxx -o result.json`,
}

// auditADCmd runs an AD audit
var auditADCmd = &cobra.Command{
	Use:   "ad",
	Short: "Audit Active Directory (on-premises)",
	Long: `Run a security audit against an on-premises Active Directory via LDAP.

Requires LDAP connectivity to a domain controller. Checks password policies,
Kerberos security, privileged accounts, delegation, ADCS certificates, and more.`,
	RunE: runAuditAD,
}

// auditAzureCmd runs an Azure AD audit
var auditAzureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Audit Azure AD / Entra ID",
	Long: `Run a security audit against Azure AD / Microsoft Entra ID.

Requires an App Registration with the following Microsoft Graph permissions:
  - User.Read.All, Group.Read.All, Directory.Read.All
  - Application.Read.All, RoleManagement.Read.Directory
  - Policy.Read.All`,
	RunE: runAuditAzure,
}

// auditIntuneCmd runs an Intune audit
var auditIntuneCmd = &cobra.Command{
	Use:   "intune",
	Short: "Audit Microsoft Intune",
	Long: `Run a security audit against Microsoft Intune (mobile device management).

Requires the same App Registration as Azure AD, plus:
  - DeviceManagementConfiguration.Read.All
  - DeviceManagementApps.Read.All
  - DeviceManagementManagedDevices.Read.All`,
	RunE: runAuditIntune,
}

// auditExchangeCmd runs an Exchange Online audit
var auditExchangeCmd = &cobra.Command{
	Use:   "exchange",
	Short: "Audit Exchange Online",
	Long: `Run a security audit against Exchange Online (email security).

Requires the same App Registration as Azure AD, plus Exchange-specific permissions.`,
	RunE: runAuditExchange,
}

// auditGoogleCmd runs a Google Workspace audit
var auditGoogleCmd = &cobra.Command{
	Use:   "google",
	Short: "Audit Google Workspace",
	Long: `Run a security audit against Google Workspace.

Requires a Service Account with domain-wide delegation and the following scopes:
  - https://www.googleapis.com/auth/admin.directory.user.readonly
  - https://www.googleapis.com/auth/admin.directory.group.readonly
  - https://www.googleapis.com/auth/admin.directory.domain.readonly`,
	RunE: runAuditGoogle,
}

func init() {
	rootCmd.AddCommand(auditCmd)

	// Add provider subcommands
	auditCmd.AddCommand(auditADCmd)
	auditCmd.AddCommand(auditAzureCmd)
	auditCmd.AddCommand(auditIntuneCmd)
	auditCmd.AddCommand(auditExchangeCmd)
	auditCmd.AddCommand(auditGoogleCmd)
	auditCmd.AddCommand(auditVerifyCmd) // v3.1.19 — integrity verification

	// Common flags on parent (inherited by all subcommands)
	auditCmd.PersistentFlags().StringVarP(&auditOutput, "output", "o", "", "Output file (default: stdout)")
	auditCmd.PersistentFlags().StringVar(&auditFormat, "format", "json", "Output format: json, json-pretty")
	auditCmd.PersistentFlags().BoolVar(&auditIncludeDetails, "include-details", true, "Include affected entities in findings (use --include-details=false to disable)")
	auditCmd.PersistentFlags().StringVar(&auditAsOf, "as-of", "", "Reference time recency detectors measure against (RFC3339, e.g. 2026-08-20T00:00:00Z). Empty (default): the real moment this audit runs. Pins RunOptions.AsOf so replaying a frozen bench on different real dates gives identical output (B_175, T_067).")

	// Asset filter flags (persistent so discover can share them).
	auditCmd.PersistentFlags().StringVar(&auditExclusionsPath, "exclusions", "", "Path to an exclusions.yaml file (asset + detector include/exclude rules)")
	auditCmd.PersistentFlags().BoolVar(&auditExclusionsDryRun, "exclusions-dry-run", false, "Compute the exclusion report without actually filtering data (preview mode)")

	// Scope flags (limit which detectors run). Run `etc-collector audit list` for the catalogue.
	auditCmd.PersistentFlags().StringVar(&scopeProfile, "scope-profile", "", "Named preset (quick, compliance, pentest) [env: AUDIT_PROFILE]")
	auditCmd.PersistentFlags().StringSliceVar(&scopeIncludeCategories, "scope-include-categories", nil, "Detector categories to include (comma-separated) [env: AUDIT_INCLUDE_CATEGORIES]")
	auditCmd.PersistentFlags().StringSliceVar(&scopeExcludeCategories, "scope-exclude-categories", nil, "Detector categories to exclude (comma-separated) [env: AUDIT_EXCLUDE_CATEGORIES]")
	auditCmd.PersistentFlags().StringSliceVar(&scopeIncludeDetectors, "scope-include-detectors", nil, "Detector IDs to include (comma-separated) [env: AUDIT_INCLUDE_DETECTORS]")
	auditCmd.PersistentFlags().StringSliceVar(&scopeExcludeDetectors, "scope-exclude-detectors", nil, "Detector IDs to exclude (comma-separated) [env: AUDIT_EXCLUDE_DETECTORS]")

	// Discovery sub-command for the scope flags.
	auditCmd.AddCommand(auditListCmd)

	// AD-specific flags
	auditADCmd.Flags().StringVar(&auditLDAPURL, "ldap-url", "", "LDAP server URL (e.g., ldaps://dc:636) [env: LDAP_URL]")
	auditADCmd.Flags().StringVar(&auditLDAPBindDN, "ldap-bind-dn", "", "LDAP bind DN [env: LDAP_BIND_DN]")
	auditADCmd.Flags().StringVar(&auditLDAPBindPass, "ldap-bind-password", "", "LDAP bind password [env: LDAP_BIND_PASSWORD]")
	auditADCmd.Flags().StringVar(&auditLDAPBaseDN, "ldap-base-dn", "", "LDAP base DN [env: LDAP_BASE_DN]")
	auditADCmd.Flags().BoolVar(&auditLDAPTLSVerify, "ldap-tls-verify", true, "Verify LDAP TLS certificates [env: LDAP_TLS_VERIFY]")
	auditADCmd.Flags().StringVar(&auditLDAPCACert, "ldap-ca-cert", "", "Path to a PEM file containing the CA that signed the DC certificate (or pre-installed in the system trust store)")
	auditADCmd.Flags().StringVar(&auditLDAPTLSMinVersion, "ldap-tls-min-version", "", "Minimum TLS version for LDAPS/StartTLS: 1.0, 1.1, 1.2, 1.3 (default: Go default = 1.2)")
	auditADCmd.Flags().BoolVar(&auditLDAPStartTLS, "ldap-start-tls", false, "Use StartTLS to upgrade an ldap:// (port 389) connection to TLS")
	auditADCmd.Flags().BoolVar(&auditNetworkProbes, "enable-network-probes", false, "Enable network probes (HTTP ADCS, DNS AXFR)")
	// T_111: --ldap-url/--ldap-bind-dn/--ldap-bind-password/--ldap-base-dn are
	// deliberately NOT MarkFlagRequired anymore — cobra rejected a missing flag
	// BEFORE RunE ever ran, which short-circuited LDAP_*/config.yaml resolution
	// before it could apply (the exact T_038 reasoning the Azure flags below
	// already document for --tenant-id/--client-id). requireLDAPConn enforces
	// the requirement after resolveLDAPConnFromSources runs, in runAuditAD.

	// Azure-specific flags
	auditAzureCmd.Flags().StringVar(&auditAzureTenantID, "tenant-id", "", "Azure AD tenant ID")
	auditAzureCmd.Flags().StringVar(&auditAzureClientID, "client-id", "", "Azure AD app client ID")
	auditAzureCmd.Flags().StringVar(&auditAzureClientSecret, "client-secret", "", "Azure AD app client secret (alternative to --client-cert)")
	auditAzureCmd.Flags().StringVar(&auditAzureClientCert, "client-cert", "", "Path to the client certificate used for app-only authentication: PEM bundle (certificate + private key) or PKCS#12/.pfx. Required by tenants that forbid client secrets. Takes precedence over --client-secret")
	auditAzureCmd.Flags().StringVar(&auditAzureClientCertPass, "client-cert-password", "", "Password protecting --client-cert (encrypted PKCS#12/.pfx)")
	auditAzureCmd.Flags().StringSliceVar(&auditAzureInclude, "include", nil, "Include additional Microsoft providers (intune,exchange)")
	auditAzureCmd.Flags().BoolVar(&auditAzureSkipPermCheck, "skip-permission-check", false, "Skip the pre-audit permission validation")
	// v3.1.30 §1 — sign-in logs deep collection
	auditAzureCmd.Flags().StringVar(&auditAzureSignInLogsMode, "azure-signin-logs-mode", "raw", "Sign-in logs collection mode: raw (default, full event stream) | aggregated (counters + topN) | off")
	auditAzureCmd.Flags().IntVar(&auditAzureSignInLogsDays, "azure-signin-logs-days", 30, "Sign-in logs lookback window in days (max 30, Graph retention)")
	auditAzureCmd.Flags().IntVar(&auditAzureSignInLogsMax, "azure-signin-logs-max", 500000, "Hard cap on sign-in events fetched (prevents OOM on large tenants)")
	auditAzureCmd.Flags().IntVar(&auditAzureSignInLogsBudget, "azure-signin-logs-budget", 300, "Time budget in seconds for sign-in logs collection (default 5min). On timeout, partial events are kept, AZURE_SIGNIN_LOGS_TIMEOUT warning is emitted, and detection still runs.")
	auditAzureCmd.Flags().BoolVar(&auditAzureAnonymizeIP, "azure-anonymize-ip", false, "Mask the last IPv4 octet of every sign-in log IP (GDPR mode)")
	// v3.1.36 — directory audits (90d, 5 security categories)
	auditAzureCmd.Flags().IntVar(&auditAzureDirectoryAuditsDays, "azure-directory-audits-days", 90, "Directory audits lookback window in days (default 90 — Graph retention for non-P1/P2)")
	auditAzureCmd.Flags().IntVar(&auditAzureDirectoryAuditsMax, "azure-directory-audits-max", 0, "Soft cap on merged directory audit events (0 = no cap)")
	auditAzureCmd.Flags().IntVar(&auditAzureDirectoryAuditsBudget, "azure-directory-audits-budget", 300, "Time budget in seconds for directory audits collection (default 5min). On timeout, partial events are kept, AZURE_DIRECTORY_AUDITS_TIMEOUT warning is emitted, and detection still runs.")
	// v3.1.38 §2 — hybrid edges (Entra ↔ AD)
	auditAzureCmd.Flags().IntVar(&auditAzureHybridLinksMax, "azure-hybrid-links-max", 0, "Soft cap on merged Entra device count for hybrid links (0 = no cap)")
	auditAzureCmd.Flags().IntVar(&auditAzureHybridLinksBudget, "azure-hybrid-links-budget", 180, "Time budget in seconds for /devices pagination (default 3min). On timeout, partial devices are kept, AZURE_HYBRID_LINKS_TIMEOUT warning is emitted.")
	auditAzureCmd.Flags().BoolVar(&auditGzipOutput, "gzip-output", false, "gzip-encode the JSON output file (.json -> .json.gz)")
	// --tenant-id and --client-id are deliberately NOT MarkFlagRequired: cobra would
	// reject the command before the azure: section of config.yaml (or AZURE_*) is ever
	// consulted, which would make the wiring pointless. They stay mandatory, but are
	// enforced AFTER resolution — azure.NewClient returns "tenant ID is required" /
	// "client ID is required" (internal/providers/azure/client.go). Same pattern T_026
	// applied to --client-secret below.
	//
	// --client-secret is deliberately NOT required: a client certificate is an
	// equally valid credential. azure.NewClient rejects the case where neither
	// is provided, with a message that names both options.

	// Intune uses same flags as Azure
	auditIntuneCmd.Flags().StringVar(&auditAzureTenantID, "tenant-id", "", "Azure AD tenant ID")
	auditIntuneCmd.Flags().StringVar(&auditAzureClientID, "client-id", "", "Azure AD app client ID")
	auditIntuneCmd.Flags().StringVar(&auditAzureClientSecret, "client-secret", "", "Azure AD app client secret")
	auditIntuneCmd.MarkFlagRequired("tenant-id")
	auditIntuneCmd.MarkFlagRequired("client-id")
	auditIntuneCmd.MarkFlagRequired("client-secret")

	// Exchange uses same flags as Azure
	auditExchangeCmd.Flags().StringVar(&auditAzureTenantID, "tenant-id", "", "Azure AD tenant ID")
	auditExchangeCmd.Flags().StringVar(&auditAzureClientID, "client-id", "", "Azure AD app client ID")
	auditExchangeCmd.Flags().StringVar(&auditAzureClientSecret, "client-secret", "", "Azure AD app client secret")
	auditExchangeCmd.MarkFlagRequired("tenant-id")
	auditExchangeCmd.MarkFlagRequired("client-id")
	auditExchangeCmd.MarkFlagRequired("client-secret")

	// Google-specific flags
	auditGoogleCmd.Flags().StringVar(&auditGoogleKeyFile, "service-account-key", "", "Path to Google service account JSON key")
	auditGoogleCmd.Flags().StringVar(&auditGoogleDomain, "domain", "", "Google Workspace domain")
	auditGoogleCmd.Flags().StringVar(&auditGoogleAdminEmail, "admin-email", "", "Admin email for domain-wide delegation")
	auditGoogleCmd.MarkFlagRequired("service-account-key")
	auditGoogleCmd.MarkFlagRequired("domain")
	auditGoogleCmd.MarkFlagRequired("admin-email")
}

// runAuditAD executes an Active Directory audit
// resolveAuditAsOf parses --as-of into a time.Time for RunOptions.AsOf. Empty input
// returns the zero time, which engine.Run already treats as "use the real moment this
// audit runs" (RunOptions.AsOf's own doc comment) — this function only parses, it
// doesn't decide the default.
func resolveAuditAsOf(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("--as-of %q is not a valid RFC3339 timestamp (e.g. 2026-08-20T00:00:00Z): %w", raw, err)
	}
	return t, nil
}

func runAuditAD(cmd *cobra.Command, args []string) error {
	// T_106 (follow-up to T_101/server.go): --ldap-bind-password puts the LDAP
	// bind secret in argv, readable by any local user via /proc/<pid>/cmdline
	// (world-readable on Linux) for as long as the process runs. T_111 wired
	// LDAP_BIND_PASSWORD/ldap.bindPassword as real fallbacks below (see
	// resolveLDAPConnFromSources) — this flag stays supported for backward
	// compatibility with existing invocations, same as server.go.
	if cmd.Flags().Changed("ldap-bind-password") {
		log.Warn("--ldap-bind-password was passed on the command line — the secret is readable by any local user for as long as this process runs (e.g. via /proc/<pid>/cmdline on Linux). Prefer the LDAP_BIND_PASSWORD environment variable or ldap.bindPassword in config.yaml instead.")
	}

	// T_111: CLI flag > LDAP_* environment variable > ldap: in config.yaml —
	// the same precedence server.go/daemon already apply via viper, applied
	// here with the firstNonEmpty helper this file already uses for the Azure
	// flags and the LDAP TLS extras just below. Before this, audit ad silently
	// ignored LDAP_URL/LDAP_BIND_DN/LDAP_BIND_PASSWORD/LDAP_BASE_DN and
	// LDAP_TLS_VERIFY entirely — confirmed live: `env LDAP_URL=... etc-collector
	// audit ad` without flags failed with cobra's `required flag(s) ... not set`
	// before ever reaching this function, which is exactly what broke the
	// README Quick Start Docker's first copyable example for every new user.
	conn := resolveLDAPConnFromSources(auditLDAPURL, auditLDAPBindDN, auditLDAPBindPass, auditLDAPBaseDN)
	if err := requireLDAPConn(conn); err != nil {
		return err
	}
	tlsVerify := resolveLDAPTLSVerify(cmd, auditLDAPTLSVerify)

	log.Info("Starting Active Directory audit",
		"ldap_url", conn.URL,
		"base_dn", conn.BaseDN,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Resolve TLS extras: CLI flag overrides env var overrides config file.
	caCert := firstNonEmpty(auditLDAPCACert, os.Getenv("LDAP_TLS_CA_CERT"), configLDAPField("TLSCACert"))
	caCertPEM := firstNonEmpty(os.Getenv("LDAP_TLS_CA_CERT_PEM"), configLDAPField("TLSCACertPEM"))
	tlsMin := firstNonEmpty(auditLDAPTLSMinVersion, os.Getenv("LDAP_TLS_MIN_VERSION"), configLDAPField("TLSMinVersion"))
	startTLS := auditLDAPStartTLS || os.Getenv("LDAP_START_TLS") == "true" || configLDAPBool("StartTLS")

	// Create LDAP provider
	ldapClient, err := ldap.NewClient(ldap.Config{
		URL:           conn.URL,
		BindDN:        conn.BindDN,
		BindPassword:  conn.BindPassword,
		BaseDN:        conn.BaseDN,
		TLSVerify:     tlsVerify,
		TLSCACert:     caCert,
		TLSCACertPEM:  caCertPEM,
		TLSMinVersion: tlsMin,
		StartTLS:      startTLS,
		Timeout:       30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("create LDAP client: %w", err)
	}

	log.Info("Connecting to LDAP...")
	if err := ldapClient.Connect(ctx); err != nil {
		return formatLDAPConnectError(err)
	}
	defer ldapClient.Close()
	log.Info("LDAP connected")

	// Create provider manager
	manager := providers.NewManager()
	if err := manager.Register(ldapClient); err != nil {
		return fmt.Errorf("register provider: %w", err)
	}

	// Create audit engine
	engine := audit.NewEngine(nil, ldapClient)

	// Try SMB/SYSVOL (optional, same credentials)
	smbServer := extractServerFromURL(conn.URL)
	smbDomain := extractDomainFromBaseDN(conn.BaseDN)
	smbUsername := extractUsernameFromBindDN(conn.BindDN)
	if smbServer != "" {
		smbClient := smb.NewClient(smb.Config{
			Server:   smbServer,
			Domain:   smbDomain,
			Username: smbUsername,
			Password: conn.BindPassword,
		})
		smbCtx, smbCancel := context.WithTimeout(ctx, 15*time.Second)
		if err := smbClient.Connect(smbCtx); err != nil {
			log.Warn("SMB/SYSVOL connection failed, continuing without", "error", err)
		} else {
			log.Info("SMB/SYSVOL connected")
			engine.SetSYSVOLProvider(smbClient)
			defer smbClient.Close()
		}
		smbCancel()
	}

	// Run audit
	// v3.1.19 — optional tier0_groups.yaml lookup. An unresolvable config dir is not
	// fatal for a one-shot CLI audit: the file is optional, so "" just means "not found"
	// (the error path matters where SECRETS are written — see saas.DefaultConfigDir).
	auditConfigDir, _ := saas.DefaultConfigDir()

	asOf, err := resolveAuditAsOf(auditAsOf)
	if err != nil {
		return err
	}

	opts := audit.RunOptions{
		IncludeDetails: auditIncludeDetails,
		Parallel:       true,
		NetworkProbes:  auditNetworkProbes,
		ConfigDir:      auditConfigDir,
		AsOf:           asOf,
	}
	applyScopeToOptions(&opts)

	// Asset filter config: CLI flag wins over inline collector.yaml section.
	exclCfg, err := loadExclusionsConfig()
	if err != nil {
		return err
	}
	opts.Exclusions = exclCfg
	opts.ExclusionsDryRun = auditExclusionsDryRun
	if exclCfg != nil {
		log.Info("Asset filters loaded",
			"rulesHash", exclCfg.Hash,
			"dryRun", auditExclusionsDryRun,
		)
	}

	log.Info("Running audit...")
	result, err := engine.Run(ctx, opts)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	log.Info("Audit completed",
		"findings", len(result.Findings),
		"score", result.Score,
		"rating", result.Rating,
		"duration", result.Duration,
	)

	// Convert to TypeScript-compatible format
	response := types.ConvertToTSFormat(result, "ad", conn.URL, conn.BaseDN, auditIncludeDetails)

	return writeAuditOutput(response)
}

// runAuditAzure executes an Azure AD audit
func runAuditAzure(cmd *cobra.Command, args []string) error {
	log.Info("Starting Azure AD / Entra ID audit",
		"tenant_id", auditAzureTenantID,
		"auth", azureAuthMethodLabel(),
	)

	// v3.1.30 §1 — reject silent fallback: --azure-signin-logs-max <= 0 must
	// fail loud rather than fall back to the 500_000 default. An operator
	// that types a negative number expects an answer, not silently-collected
	// half-data.
	if auditAzureSignInLogsMax <= 0 {
		return fmt.Errorf("--azure-signin-logs-max must be > 0 (got %d). Use the default 500000 by omitting the flag, or pass a positive cap", auditAzureSignInLogsMax)
	}

	// v3.1.32 hotfix — bumped from 10m to 30m to absorb tenants with
	// real sign-in volume (1k+ events/day × 4 event types × ~20s/page on
	// the beta endpoint can take 10-15 min on its own). The engine wraps
	// sign-in collection in a 5-min sub-context so detection still runs
	// with whatever was collected; the outer 30m caps the total CLI run.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Create Azure provider
	azureClient, err := azure.NewClient(azureConfigFromFlags())
	if err != nil {
		return fmt.Errorf("create Azure client: %w", err)
	}

	log.Info("Connecting to Azure AD...")
	if err := azureClient.Connect(ctx); err != nil {
		return fmt.Errorf("connect to Azure AD: %w", err)
	}
	defer azureClient.Close()
	log.Info("Azure AD connected")

	if !auditAzureSkipPermCheck {
		log.Info("Checking Azure permissions...")
		checks := azureClient.CheckPermissions(ctx)
		granted, missing := 0, 0
		for _, c := range checks {
			if c.Granted {
				granted++
			} else {
				missing++
				log.Warn("Permission missing", "permission", c.Permission, "error", c.Error)
			}
		}
		if missing > 0 {
			log.Warn("Some permissions are missing. Detectors that depend on them will not produce results.",
				"granted", granted, "missing", missing, "total", len(checks))
		} else {
			log.Info("All Azure permissions granted", "count", granted)
		}
	}

	// Create provider manager
	manager := providers.NewManager()
	if err := manager.Register(azureClient); err != nil {
		return fmt.Errorf("register provider: %w", err)
	}

	// Create audit engine with Azure provider
	engine := audit.NewEngine(nil, azureClient)

	// Run audit
	asOf, err := resolveAuditAsOf(auditAsOf)
	if err != nil {
		return err
	}

	opts := audit.RunOptions{
		IncludeDetails: auditIncludeDetails,
		Parallel:       true,
		AsOf:           asOf,
		// v3.1.30 §1 — sign-in logs deep collection (raw default).
		AzureSignInLogsMode:          auditAzureSignInLogsMode,
		AzureSignInLogsDays:          auditAzureSignInLogsDays,
		AzureSignInLogsMax:           auditAzureSignInLogsMax,
		AzureSignInLogsBudgetSeconds: auditAzureSignInLogsBudget,
		AzureAnonymizeIP:             auditAzureAnonymizeIP,
		// v3.1.36 — directory audits (90d, 5 security categories).
		AzureDirectoryAuditsDays:          auditAzureDirectoryAuditsDays,
		AzureDirectoryAuditsMax:           auditAzureDirectoryAuditsMax,
		AzureDirectoryAuditsBudgetSeconds: auditAzureDirectoryAuditsBudget,
		// v3.1.38 §2 — hybrid edges (Entra ↔ AD).
		AzureHybridLinksMax:           auditAzureHybridLinksMax,
		AzureHybridLinksBudgetSeconds: auditAzureHybridLinksBudget,
		// v3.1.37 §1 — Embed binary version into audit.baselineSecurity for
		// auditor traceability (which baseline policy list applied).
		CollectorVersion: Version,
	}
	applyScopeToOptions(&opts)

	log.Info("Running Azure audit...")
	result, err := engine.Run(ctx, opts)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	log.Info("Audit completed",
		"findings", len(result.Findings),
		"score", result.Score,
		"rating", result.Rating,
		"duration", result.Duration,
	)

	// Convert to TypeScript-compatible format
	response := types.ConvertToTSFormat(result, "azure", "azure://"+auditAzureTenantID, auditAzureTenantID, auditIncludeDetails)

	return writeAuditOutput(response)
}

// azureConfigFromFlags maps the Azure CLI flags onto the provider config.
// Split out of runAuditAzure so the flag → azure.Config wiring is testable
// without a tenant.
// Precedence: CLI flag > AZURE_* environment variable > azure: in config.yaml.
// The canonical statement of that rule lives in internal/config/precedence.go; this
// is the same resolution runAuditAD already applies to the LDAP TLS extras.
func azureConfigFromFlags() azure.Config {
	return azure.Config{
		TenantID:       firstNonEmpty(auditAzureTenantID, os.Getenv("AZURE_TENANT_ID"), configAzureField("TenantID")),
		ClientID:       firstNonEmpty(auditAzureClientID, os.Getenv("AZURE_CLIENT_ID"), configAzureField("ClientID")),
		ClientSecret:   firstNonEmpty(auditAzureClientSecret, os.Getenv("AZURE_CLIENT_SECRET"), configAzureField("ClientSecret")),
		ClientCertPath: firstNonEmpty(auditAzureClientCert, os.Getenv("AZURE_CLIENT_CERT"), configAzureField("ClientCertPath")),
		// No flag: a multi-line PEM is not passable as a command-line argument, so
		// only the file and the cloud carry it.
		ClientCertPEM:      firstNonEmpty(os.Getenv("AZURE_CLIENT_CERT_PEM"), configAzureField("ClientCertPEM")),
		ClientCertPassword: firstNonEmpty(auditAzureClientCertPass, os.Getenv("AZURE_CLIENT_CERT_PASSWORD"), configAzureField("ClientCertPassword")),
	}
}

// azureAuthMethodLabel names the credential the audit will use, so a support
// ticket can tell "wrong secret" from "wrong certificate" at a glance.
func azureAuthMethodLabel() string {
	if auditAzureClientCert != "" {
		return "certificate"
	}
	return "client-secret"
}

// runAuditIntune executes an Intune audit
func runAuditIntune(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("Microsoft Intune audit is coming soon.\n\nThis provider will support:\n  - Device compliance policies\n  - App protection policies\n  - Encryption enforcement\n  - Jailbroken device detection\n  - Mobile threat defense\n\nSee https://github.com/etcsec-com/etc-collector for updates")
}

// runAuditExchange executes an Exchange Online audit
func runAuditExchange(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("Exchange Online audit is coming soon.\n\nThis provider will support:\n  - Mailbox delegation review\n  - External forwarding rules\n  - DLP policy analysis\n  - Anti-spam settings\n  - Retention policies\n\nSee https://github.com/etcsec-com/etc-collector for updates")
}

// runAuditGoogle executes a Google Workspace audit
func runAuditGoogle(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("Google Workspace audit is coming soon.\n\nThis provider will support:\n  - OAuth app permissions\n  - Admin roles analysis\n  - Drive sharing audit\n  - 2FA enforcement\n  - User activity patterns\n\nSee https://github.com/etcsec-com/etc-collector for updates")
}

// auditVerifyCmd recomputes the SHA-256 integrity hash of an audit JSON
// report and compares it to the stored signature. Exit 0 = match, 1 = mismatch
// (the report has been modified since it was produced by the collector).
//
// v3.1.19 — added so an ANSSI auditor can prove the JSON they're reviewing
// is byte-identical to what the collector emitted at audit time.
var auditVerifyCmd = &cobra.Command{
	Use:   "verify <audit-report.json>",
	Short: "Verify the SHA-256 integrity signature of an audit JSON report",
	Long: `Recompute the integrity hash of an audit JSON report and compare it
to the signature embedded in .integrity.hash. Returns exit 0 if the report is
byte-identical to what the collector produced, exit 1 otherwise.

Use this when an auditor receives a JSON report and needs to prove it has
not been tampered with after the collector wrote it.`,
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		// v3.1.19 — verify against the sidecar SHA-256 file. Sidecar format:
		//   <hex-hash>  <filename>\n
		// (matches `sha256sum` so auditors can also use that tool directly.)
		sidecar := path + ".sha256"
		expected, serr := os.ReadFile(sidecar)
		if serr != nil {
			fmt.Fprintf(os.Stderr, "FAIL: missing sidecar %s (run with v3.1.19+ to produce it)\n", sidecar)
			os.Exit(1)
		}
		expectedHash := strings.TrimSpace(strings.SplitN(string(expected), " ", 2)[0])
		got := sha256.Sum256(raw)
		gotHex := hex.EncodeToString(got[:])
		if gotHex != expectedHash {
			fmt.Fprintf(os.Stderr, "FAIL: integrity MISMATCH\n  expected: %s\n  computed: %s\n  → the JSON file has been modified since it was produced.\n", expectedHash, gotHex)
			os.Exit(1)
		}
		fmt.Printf("OK — integrity verified (sha256 %s)\n", gotHex)
		return nil
	},
}

// writeAuditOutput writes the audit result to file or stdout. v3.1.19 — when
// writing to a file, also emits a sidecar <file>.sha256 containing the hex
// SHA-256 of the JSON content. Auditors verify with `sha256sum -c` or
// `etc-collector audit verify <file>`.
//
// Embedding the hash inside the JSON itself was rejected after smoke tests
// proved that Go's encoding/json round-trip is not byte-identical when
// Finding.Details contains map[string]interface{} (int → float64 on
// unmarshal, etc.). The sidecar approach is 100% reliable and matches
// established conventions (Linux package signatures, distribution releases).
func writeAuditOutput(response *types.AuditResponse) error {
	var data []byte
	var err error

	if auditFormat == "json-pretty" {
		data, err = json.MarshalIndent(response, "", "  ")
	} else {
		data, err = json.Marshal(response)
	}
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}

	// Add trailing newline
	data = append(data, '\n')

	if auditOutput == "" {
		_, err = os.Stdout.Write(data)
		return err
	}

	// v3.1.30 §1 — optional gzip wrap. Hash + sidecar are computed on the
	// gzipped bytes so the verify path stays uniform (one hash for whatever
	// is on disk).
	outputPath := auditOutput
	payload := data
	if auditGzipOutput {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(data); err != nil {
			return fmt.Errorf("gzip output: %w", err)
		}
		if err := gz.Close(); err != nil {
			return fmt.Errorf("gzip output close: %w", err)
		}
		payload = buf.Bytes()
		if !strings.HasSuffix(outputPath, ".gz") {
			outputPath += ".gz"
		}
	}

	if err := os.WriteFile(outputPath, payload, 0644); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	// v3.1.19 — write a sidecar SHA-256 digest. Auditor uses it via
	// `etc-collector audit verify` or directly `sha256sum -c <file>.sha256`.
	sum := sha256.Sum256(payload)
	digestPath := outputPath + ".sha256"
	digestLine := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), filepath.Base(outputPath))
	if err := os.WriteFile(digestPath, []byte(digestLine), 0644); err != nil {
		// Non-fatal — log but don't abort the audit.
		log.Warn("Failed to write integrity sidecar", "path", digestPath, "error", err.Error())
	} else {
		log.Info("Integrity sidecar written", "file", digestPath)
	}

	log.Info("Results written", "file", outputPath, "size", len(payload))
	return nil
}

// firstNonEmpty returns the first non-empty string from the arguments.
//
// Thin alias over config.Resolve so the precedence rule has exactly one definition
// (internal/config/precedence.go). Callers pass sources already ordered
// flag → environment → config.yaml.
func firstNonEmpty(values ...string) string {
	return config.Resolve(values...)
}

// configLDAPField returns a string field from cfg.LDAP by name; "" if cfg is nil.
func configLDAPField(name string) string {
	if cfg == nil {
		return ""
	}
	switch name {
	case "URL":
		return cfg.LDAP.URL
	case "BindDN":
		return cfg.LDAP.BindDN
	case "BindPassword":
		return cfg.LDAP.BindPassword
	case "BaseDN":
		return cfg.LDAP.BaseDN
	case "TLSCACert":
		return cfg.LDAP.TLSCACert
	case "TLSCACertPEM":
		return cfg.LDAP.TLSCACertPEM
	case "TLSMinVersion":
		return cfg.LDAP.TLSMinVersion
	}
	return ""
}

// resolvedLDAPConn holds the 4 primary LDAP connection fields after applying
// CLI flag > LDAP_* environment variable > ldap: in config.yaml — the same
// precedence server.go/daemon already apply via viper.BindPFlag/BindEnv.
// audit ad and discover ad share this (T_111).
type resolvedLDAPConn struct {
	URL          string
	BindDN       string
	BindPassword string
	BaseDN       string
}

// resolveLDAPConnFromSources applies that precedence via firstNonEmpty, the
// exact mechanism this file already uses for the Azure flags
// (azureConfigFromFlags) and for the LDAP TLS extras in runAuditAD/
// runDiscoverAD. Before T_111, audit ad and discover ad read ONLY the flag
// values — LDAP_URL/LDAP_BIND_DN/LDAP_BIND_PASSWORD/LDAP_BASE_DN were silently
// ignored, unlike server/daemon, which broke the README Quick Start Docker's
// first copyable example (env vars set, no flags) for every new user.
func resolveLDAPConnFromSources(url, bindDN, bindPass, baseDN string) resolvedLDAPConn {
	return resolvedLDAPConn{
		URL:          firstNonEmpty(url, os.Getenv("LDAP_URL"), configLDAPField("URL")),
		BindDN:       firstNonEmpty(bindDN, os.Getenv("LDAP_BIND_DN"), configLDAPField("BindDN")),
		BindPassword: firstNonEmpty(bindPass, os.Getenv("LDAP_BIND_PASSWORD"), configLDAPField("BindPassword")),
		BaseDN:       firstNonEmpty(baseDN, os.Getenv("LDAP_BASE_DN"), configLDAPField("BaseDN")),
	}
}

// requireLDAPConn replaces the cobra MarkFlagRequired check audit ad/discover
// ad used before T_111 — that mechanism ran BEFORE RunE, rejecting the command
// before LDAP_*/config.yaml were ever consulted (same reasoning as the Azure
// tenant-id/client-id comment above, T_038/audit_azurecert_test.go). Enforced
// here, after resolution, so all three sources genuinely get a chance to
// supply the value.
func requireLDAPConn(c resolvedLDAPConn) error {
	var missing []string
	if c.URL == "" {
		missing = append(missing, "--ldap-url / LDAP_URL")
	}
	if c.BindDN == "" {
		missing = append(missing, "--ldap-bind-dn / LDAP_BIND_DN")
	}
	if c.BindPassword == "" {
		missing = append(missing, "--ldap-bind-password / LDAP_BIND_PASSWORD")
	}
	if c.BaseDN == "" {
		missing = append(missing, "--ldap-base-dn / LDAP_BASE_DN")
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("missing required LDAP connection info: %s (also settable via ldap: in config.yaml)", strings.Join(missing, ", "))
}

// resolveLDAPTLSVerify applies the same flag > env > config precedence as
// resolveLDAPConnFromSources, for the one boolean in the connection set.
// cmd.Flags().Changed is required here (unlike firstNonEmpty) because a bool
// flag's default value (true) is indistinguishable from an explicit
// --ldap-tls-verify=true — the same reason server.go delegates this to
// viper.BindPFlag/BindEnv, which does the identical Changed-based fallback
// internally. Before T_111, LDAP_TLS_VERIFY (documented in
// environment-variables.md alongside the other LDAP_TLS_* vars) had no effect
// on audit ad/discover ad at all.
func resolveLDAPTLSVerify(cmd *cobra.Command, flagVal bool) bool {
	if cmd.Flags().Changed("ldap-tls-verify") {
		return flagVal
	}
	if v, ok := os.LookupEnv("LDAP_TLS_VERIFY"); ok {
		return v == "true"
	}
	if cfg != nil {
		return cfg.LDAP.TLSVerify
	}
	return flagVal
}

// configAzureField returns a string field from cfg.Azure by name; "" if cfg is nil.
// Exact mirror of configLDAPField — the asymmetry between the two was the whole of
// B_033: ldap: looked like proof that config.yaml worked, while azure: was parsed,
// displayed by the admin API, and never used to run anything.
func configAzureField(name string) string {
	if cfg == nil {
		return ""
	}
	switch name {
	case "TenantID":
		return cfg.Azure.TenantID
	case "ClientID":
		return cfg.Azure.ClientID
	case "ClientSecret":
		return cfg.Azure.ClientSecret
	case "ClientCertPath":
		return cfg.Azure.ClientCertPath
	case "ClientCertPEM":
		return cfg.Azure.ClientCertPEM
	case "ClientCertPassword":
		return cfg.Azure.ClientCertPassword
	}
	return ""
}

// configLDAPBool returns a bool field from cfg.LDAP by name; false if cfg is nil.
func configLDAPBool(name string) bool {
	if cfg == nil {
		return false
	}
	switch name {
	case "StartTLS":
		return cfg.LDAP.StartTLS
	}
	return false
}

// formatLDAPConnectError pretty-prints a *ldap.ConnectError so the user sees
// the structured code, fix and doc anchor on stderr instead of a raw chain.
func formatLDAPConnectError(err error) error {
	var ce *ldap.ConnectError
	if errors.As(err, &ce) {
		return fmt.Errorf("LDAP connection failed:\n%s", ce.PrettyPrint())
	}
	return fmt.Errorf("connect to LDAP: %w", err)
}

// loadExclusionsConfig resolves the asset-filter config from (in order):
// 1. --exclusions flag (path to a YAML file)
// 2. audit.assetFilters inline section in collector.yaml
// Returns nil if neither is present.
func loadExclusionsConfig() (*exclusions.Config, error) {
	if auditExclusionsPath != "" {
		cfg, err := exclusions.Load(auditExclusionsPath)
		if err != nil {
			return nil, fmt.Errorf("load exclusions %s: %w", auditExclusionsPath, err)
		}
		return cfg, nil
	}
	if cfg != nil && len(cfg.Audit.AssetFilters) > 0 {
		ex, err := exclusions.LoadFromMap(cfg.Audit.AssetFilters)
		if err != nil {
			return nil, fmt.Errorf("load inline audit.assetFilters: %w", err)
		}
		return ex, nil
	}
	return nil, nil
}

// applyScopeToOptions resolves the CLI/env/YAML scope and writes it into opts.
// Precedence per source: CLI flag > env var > YAML config.
// Warnings (unknown profile / category / detector ID) are logged but never fatal.
func applyScopeToOptions(opts *audit.RunOptions) {
	scope := buildScopeFromSources()
	if scope.IsEmpty() {
		return
	}
	warnings := scope.ApplyTo(opts, audit.DefaultRegistry)
	for _, w := range warnings {
		log.Warn("scope: " + w)
	}
	log.Info("Scope applied",
		"profile", scope.Profile,
		"selected", len(opts.DetectorIDs),
		"total", audit.DefaultRegistry.Count(),
	)
}

// buildScopeFromSources merges CLI flag → env var → YAML config for each field.
func buildScopeFromSources() audit.Scope {
	s := audit.Scope{}

	s.Profile = firstNonEmpty(scopeProfile, os.Getenv("AUDIT_PROFILE"), configAuditScopeProfile())

	mergeStrings := func(flag []string, envName string, yaml []string) []string {
		if len(flag) > 0 {
			return flag
		}
		if v := os.Getenv(envName); v != "" {
			return splitComma(v)
		}
		return yaml
	}
	yamlScope := configAuditScope()
	s.IncludeCategories = toCategories(mergeStrings(scopeIncludeCategories, "AUDIT_INCLUDE_CATEGORIES", yamlScope.IncludeCategories))
	s.ExcludeCategories = toCategories(mergeStrings(scopeExcludeCategories, "AUDIT_EXCLUDE_CATEGORIES", yamlScope.ExcludeCategories))
	s.IncludeDetectors = mergeStrings(scopeIncludeDetectors, "AUDIT_INCLUDE_DETECTORS", yamlScope.IncludeDetectors)
	s.ExcludeDetectors = mergeStrings(scopeExcludeDetectors, "AUDIT_EXCLUDE_DETECTORS", yamlScope.ExcludeDetectors)
	return s
}

func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func toCategories(values []string) []audit.DetectorCategory {
	if len(values) == 0 {
		return nil
	}
	out := make([]audit.DetectorCategory, 0, len(values))
	for _, v := range values {
		out = append(out, audit.DetectorCategory(strings.TrimSpace(v)))
	}
	return out
}

// configAuditScope returns the YAML-loaded scope (or zero value when no config).
func configAuditScope() (out struct {
	IncludeCategories []string
	ExcludeCategories []string
	IncludeDetectors  []string
	ExcludeDetectors  []string
}) {
	if cfg == nil {
		return
	}
	out.IncludeCategories = cfg.Audit.Scope.IncludeCategories
	out.ExcludeCategories = cfg.Audit.Scope.ExcludeCategories
	out.IncludeDetectors = cfg.Audit.Scope.IncludeDetectors
	out.ExcludeDetectors = cfg.Audit.Scope.ExcludeDetectors
	return
}

func configAuditScopeProfile() string {
	if cfg == nil {
		return ""
	}
	return cfg.Audit.Scope.Profile
}

// auditListCmd dumps available categories, profiles and detector IDs so users
// know what to put in the --scope-* flags.
var auditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available detector categories, profiles and IDs (use to discover --scope-* values)",
	RunE: func(cmd *cobra.Command, args []string) error {
		reg := audit.DefaultRegistry
		fmt.Fprintln(os.Stdout, "PROFILES")
		for _, name := range audit.ListProfiles() {
			cats, _ := audit.ProfileCategoriesPublic(name)
			parts := make([]string, len(cats))
			for i, c := range cats {
				parts[i] = string(c)
			}
			fmt.Fprintf(os.Stdout, "  %-20s %s\n", name, strings.Join(parts, ", "))
		}
		// Framework profiles resolve to detector ID lists rather than
		// categories. List them with an "(N detectors)" hint.
		for _, name := range audit.FrameworkProfiles() {
			scope := audit.Scope{Profile: name}
			ids, _ := scope.Resolve(reg)
			fmt.Fprintf(os.Stdout, "  %-20s %d detectors (framework-tagged)\n", name, len(ids))
		}

		fmt.Fprintln(os.Stdout, "\nCATEGORIES (count = registered detectors)")
		cats := reg.Categories()
		catNames := make([]string, 0, len(cats))
		for _, c := range cats {
			catNames = append(catNames, string(c))
		}
		sort.Strings(catNames)
		for _, name := range catNames {
			ds := reg.GetByCategory(audit.DetectorCategory(name))
			fmt.Fprintf(os.Stdout, "  %-22s %3d\n", name, len(ds))
		}

		fmt.Fprintln(os.Stdout, "\nDETECTORS (id, category)")
		all := reg.All()
		ids := make([]string, len(all))
		idx := make(map[string]audit.Detector, len(all))
		for i, d := range all {
			ids[i] = d.ID()
			idx[d.ID()] = d
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(os.Stdout, "  %-50s %s\n", id, idx[id].Category())
		}
		fmt.Fprintf(os.Stdout, "\nTotal: %d detectors across %d categories, %d profiles\n",
			len(all), len(cats), len(audit.ListProfiles()))
		return nil
	},
}
