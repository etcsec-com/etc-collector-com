package upgrade

import "fmt"

// Code is a machine-readable error identifier emitted by the upgrade flow.
// Both the CLI and the SaaS daemon wrap their failures in one of these so
// the SaaS UI (and the user) can render a deterministic message + remediation
// instead of trying to parse free-form Go errors.
//
// Inspired by the LDAP_* taxonomy added in v3.1.12 — same idea: let the UI
// switch on a stable string, never on a translated free-form sentence.
type Code string

const (
	// Pre-flight (fail fast, no changes made)
	CodeDiskInsufficient   Code = "UPGRADE_DISK_INSUFFICIENT"
	CodeTmpInsufficient    Code = "UPGRADE_TMP_INSUFFICIENT"
	CodePermissionDenied   Code = "UPGRADE_PERMISSION_DENIED"
	CodeServiceManagerNone Code = "UPGRADE_SERVICE_MANAGER_UNKNOWN"
	CodeNetworkUnreachable Code = "UPGRADE_NETWORK_UNREACHABLE"
	CodeVersionNotFound    Code = "UPGRADE_VERSION_NOT_FOUND"
	CodeLockHeld           Code = "UPGRADE_LOCK_HELD"
	CodeAlreadyAtVersion   Code = "UPGRADE_ALREADY_AT_VERSION"
	CodeTargetNotFound     Code = "UPGRADE_TARGET_NOT_FOUND"

	// Download / verify
	CodeDownloadFailed   Code = "UPGRADE_DOWNLOAD_FAILED"
	CodeChecksumMismatch Code = "UPGRADE_CHECKSUM_MISMATCH"
	CodeExtractFailed    Code = "UPGRADE_EXTRACT_FAILED"
	CodeBinaryInvalid    Code = "UPGRADE_BINARY_INVALID"

	// Swap / restart
	CodeBackupFailed       Code = "UPGRADE_BACKUP_FAILED"
	CodeReplaceFailed      Code = "UPGRADE_REPLACE_FAILED"
	CodeServiceStopFailed  Code = "UPGRADE_SERVICE_STOP_FAILED"
	CodeServiceStartFailed Code = "UPGRADE_SERVICE_START_FAILED"
	CodeRestartTimeout     Code = "UPGRADE_RESTART_TIMEOUT"
	CodeHealthCheckFailed  Code = "UPGRADE_HEALTHCHECK_FAILED"

	// Rollback
	CodeRollbackUnavailable Code = "UPGRADE_ROLLBACK_NOT_AVAILABLE"
	CodeRollbackFailed      Code = "UPGRADE_ROLLBACK_FAILED"

	// Generic
	CodeInternal Code = "UPGRADE_INTERNAL_ERROR"
)

// Error is a structured upgrade error. It carries both a stable Code (for the
// UI / log routing) and a human-readable Remediation telling the operator
// exactly what to do next — the message-only flow we ship today produces logs
// that nobody knows what to do with.
type Error struct {
	Code        Code
	Message     string // short, end-user-facing
	Remediation string // imperative one-liner: "free disk space then re-run …"
	Cause       error  // optional underlying error (preserved for diagnostics)
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

// newErr builds an Error in one line — most callsites need exactly this.
func newErr(code Code, message, remediation string, cause error) *Error {
	return &Error{Code: code, Message: message, Remediation: remediation, Cause: cause}
}
