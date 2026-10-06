package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Well-known safe SIDs that should have these privileges. Shared with
// privilege-seloaddriver-abuse.go, the sibling detector in this package that
// filters against the same safe set.
var safePrivilegeSIDs = map[string]bool{
	"S-1-5-32-544": true, // BUILTIN\Administrators
	"S-1-5-18":     true, // LOCAL SYSTEM
	"S-1-5-19":     true, // LOCAL SERVICE
	"S-1-5-20":     true, // NETWORK SERVICE
}

func hasUnsafeSIDs(sids []string) []string {
	var unsafe []string
	for _, sid := range sids {
		if !safePrivilegeSIDs[sid] {
			unsafe = append(unsafe, sid)
		}
	}
	return unsafe
}

// safeSeDebugSIDs is SeDebugPrivilege's OWN safe set - deliberately not
// shared with safePrivilegeSIDs (SeLoadDriverPrivilege's allowlist in this
// same package). Source: Microsoft Learn "Debug programs" security policy
// setting reference - the documented default is "members of the
// Administrators group" only (S-1-5-32-544); no other GPO default value
// table row lists LOCAL SERVICE or NETWORK SERVICE. LOCAL SYSTEM is safe to
// exclude too even though it isn't in that GPO default-values table: per
// Microsoft's Win32 "LocalSystem Account" reference, LocalSystem's token
// carries SE_DEBUG_NAME enabled unconditionally, so it holds the privilege
// regardless of what the User Rights Assignment database says. LOCAL
// SERVICE and NETWORK SERVICE do NOT - their documented default privilege
// sets (Win32 "LocalService Account" / "NetworkService Account" references)
// contain neither SE_DEBUG_NAME nor SE_TCB_NAME nor SE_LOAD_DRIVER_NAME. A
// GPO that explicitly grants SeDebugPrivilege to either is a real widening
// (a compromised network-facing service account could then read LSASS
// memory as itself) that the previous shared allowlist silently missed.
var safeSeDebugSIDs = map[string]bool{
	"S-1-5-32-544": true, // BUILTIN\Administrators
	"S-1-5-18":     true, // LOCAL SYSTEM (SE_DEBUG_NAME enabled by default)
}

// SeDebugAbuseDetector checks if SeDebugPrivilege is assigned to non-admin accounts
type SeDebugAbuseDetector struct {
	audit.BaseDetector
}

func NewSeDebugAbuseDetector() *SeDebugAbuseDetector {
	return &SeDebugAbuseDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGE_SEDEBUG_ABUSE", audit.CategoryGPO),
	}
}

func (d *SeDebugAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "SeDebugPrivilege Assigned to Non-Administrators",
		Description: "The SeDebugPrivilege user right is assigned to accounts beyond the Administrators group. This privilege allows debugging any process, enabling credential extraction from LSASS memory, process injection, and full system compromise.",
		Count:       0,
	}

	sids := helpers.FindPrivilegeRight(data.GPOPolicies, func(pr *audit.PrivilegeRights) []string {
		return pr.SeDebugPrivilege
	})

	var unsafe []string
	for _, sid := range sids {
		if !safeSeDebugSIDs[sid] {
			unsafe = append(unsafe, sid)
		}
	}
	finding.Count = len(unsafe)
	if len(unsafe) > 0 {
		finding.Details = map[string]interface{}{
			"unsafeSIDs":     unsafe,
			"recommendation": "Remove SeDebugPrivilege from all accounts except the Administrators group.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSeDebugAbuseDetector())
}
