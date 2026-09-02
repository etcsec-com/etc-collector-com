// Package trial implements the anonymous trial enrollment mode used by
// etcsec.com/trial. The trial flow is completely isolated from the SaaS/fleet
// flow: distinct endpoints (/v1/trial/*), distinct token prefixes (tcol_/tapi_),
// no on-disk persistence, no service installation, ephemeral lifecycle.
package trial

import (
	"time"
)

// Token prefixes — enforced at runtime by the client guard.
const (
	EnrollTokenPrefix = "tcol_"
	APITokenPrefix    = "tapi_"
)

// DefaultBaseURL is the production trial-service base URL.
const DefaultBaseURL = "https://etcsec.com/v1/trial"

// DefaultIdleTimeout is the maximum duration the trial collector stays alive
// without receiving a command before exiting cleanly.
const DefaultIdleTimeout = 20 * time.Minute

// Supported command types (subset of the full fleet set).
const (
	CmdTestConnectionAD    = "TEST_CONNECTION_AD"
	CmdTestConnectionAzure = "TEST_CONNECTION_AZURE"
	CmdRunAuditAD          = "RUN_AUDIT_AD"
	CmdRunAuditAzure       = "RUN_AUDIT_AZURE"
)

// EnrollRequest is the body of POST /v1/trial/enroll.
type EnrollRequest struct {
	EnrollmentToken  string `json:"enrollmentToken"`
	Hostname         string `json:"hostname"`
	OsType           string `json:"osType"`
	Arch             string `json:"arch"`
	CollectorVersion string `json:"collectorVersion"`
	CollectorEdition string `json:"collectorEdition"`
}

// EnrollResponse is the response of POST /v1/trial/enroll.
type EnrollResponse struct {
	CollectorID  string `json:"collectorId"`
	APIToken     string `json:"apiToken"`
	PollInterval int    `json:"pollInterval"` // seconds
}

// Command is a single command returned by GET /v1/trial/commands.
type Command struct {
	ID     string                 `json:"id"`
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params"`
}

// CommandsResponse wraps one or many commands. The server may return either
// a single command or a list; we accept both.
type CommandsResponse struct {
	Commands []Command `json:"commands"`
	// Single-command convenience fields (server may populate these instead of Commands).
	ID     string                 `json:"id,omitempty"`
	Type   string                 `json:"type,omitempty"`
	Params map[string]interface{} `json:"params,omitempty"`
	// Status == "completed" means the session is closed; the collector should exit.
	Status string `json:"status,omitempty"`
}

// ResultError mirrors saas.ResultError but kept separate to avoid import coupling.
type ResultError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// CommandResult is the body of POST /v1/trial/commands/:id/result.
type CommandResult struct {
	Status      string       `json:"status"` // "success" | "error"
	StartedAt   string       `json:"startedAt"`
	CompletedAt string       `json:"completedAt"`
	Result      interface{}  `json:"result,omitempty"`
	Error       *ResultError `json:"error,omitempty"`
}

// Session holds the in-memory state of a trial run. Nothing is persisted.
type Session struct {
	BaseURL      string
	CollectorID  string
	APIToken     string
	PollInterval time.Duration
	IdleTimeout  time.Duration
	LastCommand  time.Time
}
