package saas

import (
	"encoding/json"
	"fmt"
)

// === ENROLLMENT ===

// EnrollRequest is the request body for POST /api/fleet/enroll
type EnrollRequest struct {
	EnrollmentToken  string   `json:"enrollmentToken"`
	CollectorVersion string   `json:"collectorVersion"`
	CollectorEdition string   `json:"collectorEdition"` // "community" or "pro"
	Hostname         string   `json:"hostname"`
	OsType           string   `json:"osType"`
	OsVersion        string   `json:"osVersion"`
	Arch             string   `json:"arch"`
	Capabilities     []string `json:"capabilities"`
}

// EnrollResponse is the response from POST /api/fleet/enroll
type EnrollResponse struct {
	Success     bool            `json:"success"`
	CollectorID string          `json:"collectorId"`
	ApiKey      string          `json:"apiKey"`
	Config      CollectorConfig `json:"config"`

	// CommandSigningPublicKeys — K3 (T_045). Additive: absent on a backend that hasn't
	// shipped signing yet. See CommandSigningKey.
	CommandSigningPublicKeys []CommandSigningKey `json:"commandSigningPublicKeys,omitempty"`
}

// CommandSigningKey is one Ed25519 verification key the collector trusts for command
// signatures (K3, T_045). The cloud maintains a small rotating set (current + next);
// the collector accepts a signature whose kid matches one of these AND falls inside
// that key's notBefore/notAfter window. Delivered on EnrollResponse and, additively, on
// CommandsResponse and HealthResponse — so an already-enrolled collector gets a key
// without re-enrolling.
type CommandSigningKey struct {
	Kid       string `json:"kid"`
	PublicKey string `json:"publicKey"`           // base64std, 32 raw Ed25519 public key bytes
	NotBefore string `json:"notBefore,omitempty"` // RFC3339; empty = no lower bound
	NotAfter  string `json:"notAfter,omitempty"`  // RFC3339; empty = no upper bound
}

// CollectorConfig is the configuration returned by the SaaS backend
type CollectorConfig struct {
	LDAP    *SaaSLDAPConfig   `json:"ldap,omitempty"`
	Azure   *SaaSAzureConfig  `json:"azure,omitempty"`
	Polling SaaSPollingConfig `json:"polling"`
}

// SaaSLDAPConfig is the LDAP config provided by the SaaS backend
type SaaSLDAPConfig struct {
	URL           string `json:"url"`
	BindDN        string `json:"bindDN"`
	BindPassword  string `json:"bindPassword"`
	BaseDN        string `json:"baseDN"`
	TLSVerify     bool   `json:"tlsVerify"`
	TLSCACert     string `json:"tlsCaCert,omitempty"`
	TLSMinVersion string `json:"tlsMinVersion,omitempty"`
	StartTLS      bool   `json:"startTLS,omitempty"`

	// AssetFilters is the include/exclude config for this collector. Pushed by
	// the SaaS via UPDATE_ASSET_FILTERS_AD and persisted in credentials.json.
	// Stored as a raw map so this file stays free of the exclusions import.
	// Converted at audit time by internal/audit/exclusions.LoadFromMap.
	AssetFilters map[string]interface{} `json:"assetFilters,omitempty"`
}

// IsConfigured returns true if the LDAP config has a non-empty URL.
// Handles nil pointer: (*SaaSLDAPConfig)(nil).IsConfigured() returns false.
func (c *SaaSLDAPConfig) IsConfigured() bool {
	return c != nil && c.URL != ""
}

// SaaSAzureConfig is the Azure config provided by the SaaS backend
type SaaSAzureConfig struct {
	TenantID     string `json:"tenantId"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// IsConfigured returns true if the Azure config has tenant and client IDs.
// Handles nil pointer: (*SaaSAzureConfig)(nil).IsConfigured() returns false.
func (c *SaaSAzureConfig) IsConfigured() bool {
	return c != nil && c.TenantID != "" && c.ClientID != ""
}

// SaaSPollingConfig holds polling intervals from the SaaS backend
type SaaSPollingConfig struct {
	IntervalSeconds        int `json:"intervalSeconds"`                  // Scheduled audit interval (e.g. 86400 = 24h)
	CommandIntervalSeconds int `json:"commandIntervalSeconds,omitempty"` // Command polling interval (default 30s)
	CommandTimeoutSeconds  int `json:"commandTimeoutSeconds"`
}

// === COMMANDS ===

// CommandsResponse is the response from GET /api/fleet/collectors/:id/commands
type CommandsResponse struct {
	Commands   []Command `json:"commands"`
	NextPollAt string    `json:"nextPollAt"`

	// CommandSigningPublicKeys — K3 (T_045), additive. See CommandSigningKey. This is
	// how a collector that enrolled before signing existed still gets a key, without
	// re-enrolling: it rides the poll it already does every 30s.
	CommandSigningPublicKeys []CommandSigningKey `json:"commandSigningPublicKeys,omitempty"`
}

// CommandSignature is the additive Ed25519 signature envelope on a Command (K3,
// T_045). Absent on any command created before the cloud starts signing, or during
// phase 2 for backends/collectors mid-migration — see checkCommandSignature.
type CommandSignature struct {
	Kid string `json:"kid"`
	Sig string `json:"sig"` // base64std, 64 raw Ed25519 signature bytes
}

// Command represents a command from the SaaS backend
type Command struct {
	CommandID  string                 `json:"commandId"`
	Type       string                 `json:"type"` // RUN_AUDIT, UPDATE_CONFIG, HEALTH_CHECK, RESTART
	Parameters map[string]interface{} `json:"parameters"`
	CreatedAt  string                 `json:"createdAt"`
	ExpiresAt  string                 `json:"expiresAt"`

	// CollectorID — K3 (T_045). The cloud adds this to the envelope so the collector
	// doesn't have to reinject its own ID from the poll URL when reconstructing
	// SIGN_INPUT; also the field checkCommandSignature compares against
	// Credentials.CollectorID to refuse a command signed for a different collector.
	CollectorID string `json:"collectorId,omitempty"`

	// Signature — K3 (T_045). Additive; nil means unsigned (pre-migration command, or
	// a backend/collector on either side of the rollout that doesn't have it yet).
	Signature *CommandSignature `json:"signature,omitempty"`

	// parametersRaw holds the exact bytes of the "parameters" field as received on the
	// wire, captured by UnmarshalJSON below. K3 (T_045): SIGN_INPUT must be built from
	// these exact bytes, never from a Go re-marshal of the Parameters map — json.Marshal
	// doesn't reproduce the signer's byte-for-byte output (map key order, spacing),
	// which is exactly the class of bug this design was locked to avoid. Unexported:
	// an internal verification detail, not part of the wire format.
	parametersRaw json.RawMessage
}

// UnmarshalJSON captures parametersRaw (the exact bytes of the incoming "parameters"
// field) alongside the normal decode into the Parameters map, so
// checkCommandSignature/buildSignInput never has to re-serialize a Go value to
// reconstruct what was signed. Every existing caller that reads cmd.Parameters as a
// map is unaffected — that decode still happens, unchanged.
func (c *Command) UnmarshalJSON(data []byte) error {
	type commandAlias Command
	aux := &struct {
		Parameters json.RawMessage `json:"parameters"`
		*commandAlias
	}{
		commandAlias: (*commandAlias)(c),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	c.parametersRaw = aux.Parameters
	if len(aux.Parameters) > 0 {
		if err := json.Unmarshal(aux.Parameters, &c.Parameters); err != nil {
			return fmt.Errorf("unmarshal command parameters: %w", err)
		}
	}
	return nil
}

// Command type constants
const (
	// AD Commands
	CmdRunAuditAD           = "RUN_AUDIT_AD"
	CmdUpdateConfigAD       = "UPDATE_CONFIG_AD"
	CmdTestConnectionAD     = "TEST_CONNECTION_AD"
	CmdDiscoverAD           = "DISCOVER_AD"
	CmdUpdateAssetFiltersAD = "UPDATE_ASSET_FILTERS_AD"

	// Azure Commands
	CmdRunAuditAzure         = "RUN_AUDIT_AZURE"
	CmdUpdateConfigAzure     = "UPDATE_CONFIG_AZURE"
	CmdTestConnectionAzure   = "TEST_CONNECTION_AZURE"
	CmdCheckPermissionsAzure = "CHECK_PERMISSIONS_AZURE"

	// General Commands
	CmdHealthCheck     = "HEALTH_CHECK"
	CmdRestart         = "RESTART"
	CmdGetLogs         = "GET_LOGS"
	CmdUpdateCollector = "UPDATE_COLLECTOR"
)

// === RESULTS ===

// CommandResult is the request body for POST /api/fleet/collectors/:id/results
type CommandResult struct {
	CommandID   string       `json:"commandId"`
	Status      string       `json:"status"` // "received" | "success" | "error"
	StartedAt   string       `json:"startedAt"`
	CompletedAt string       `json:"completedAt"`
	Result      interface{}  `json:"result,omitempty"`
	Error       *ResultError `json:"error,omitempty"`
}

// ResultError is a structured error in command results
type ResultError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// === HEALTH ===

// ComponentError represents an error on a specific component for health reporting
type ComponentError struct {
	Component string `json:"component"`      // "ldap", "azure", "audit_ad", "audit_azure", "daemon"
	Code      string `json:"code,omitempty"` // structured error code e.g. "LDAP_CONNECT_FAILED", "CRASH_RECOVERY"
	Message   string `json:"message"`
	Since     string `json:"since"` // RFC3339
	Count     int    `json:"count"`
}

// HealthReport is the request body for POST /api/fleet/collectors/:id/health
type HealthReport struct {
	Status          string           `json:"status"` // "healthy"|"degraded"|"unhealthy"
	Uptime          float64          `json:"uptime"`
	MemoryUsageMB   float64          `json:"memoryUsageMB"`
	LdapConnected   bool             `json:"ldapConnected"`
	AzureConnected  bool             `json:"azureConnected"`
	Version         string           `json:"version"`
	Edition         string           `json:"edition"` // "community" or "pro"
	Providers       []string         `json:"providers,omitempty"`
	LastCommandAt   string           `json:"lastCommandAt,omitempty"`
	LastErrorAt     string           `json:"lastErrorAt,omitempty"`
	Errors          []ComponentError `json:"errors,omitempty"`
	ConfigUpdatedAt string           `json:"configUpdatedAt,omitempty"` // ISO timestamp when config was last updated from local GUI

	// CommandSigning — K3 (T_045), additive. Lets TL Cloud's dashboard measure fleet
	// migration before enforcement (phase 4) is ever proposed — see commandSigningStatus.
	CommandSigning *CommandSigningStatus `json:"commandSigning,omitempty"`
}

// CommandSigningStatus reports this collector's command-signature verification state
// (K3, T_045). UnsignedAccepted is the field that matters most: without it, a fleet
// dashboard reads green while an active downgrade is happening — every unsigned
// command is still accepted in phase 2, so the state alone can't show that.
type CommandSigningStatus struct {
	State            string `json:"state"`         // "unverified" (no keys installed) | "verifying" (keys installed, checked) | "enforcing" (future — not implemented by this ticket)
	Kid              string `json:"kid,omitempty"` // most recently used to verify a command; empty if none verified yet
	UnsignedAccepted int    `json:"unsignedAccepted"`
}

// HealthResponse is the response body from POST /api/fleet/collectors/:id/health.
type HealthResponse struct {
	// CommandSigningPublicKeys — K3 (T_045), additive. See CommandSigningKey. Backfills
	// the already-enrolled fleet: this response rides the health-check the collector
	// already sends every cycle, so no re-enrollment is needed to receive a key.
	CommandSigningPublicKeys []CommandSigningKey `json:"commandSigningPublicKeys,omitempty"`
}

// === UNENROLL ===

// UnenrollResponse is the response from POST /api/fleet/collectors/:id/unenroll
type UnenrollResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
