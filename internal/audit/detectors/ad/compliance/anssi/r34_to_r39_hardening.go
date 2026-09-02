package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R37-R39: Windows hardening (DC-side) and audit policy.
//
//   R37 — AppLocker / WDAC (heuristic GPO presence only)
//   R38 — Advanced Audit Policy enabled (subcategories)
//   R39 — Security Event log size + retention
//
// v3.1.21 dedup: R34 (LSA Protection, WDigest) and R35 (Credential Guard)
// removed — they checked the exact same registry keys as the pre-existing
// custom detectors (LSA_PROTECTION_DISABLED, WDIGEST_ENABLED,
// CREDENTIAL_GUARD_DISABLED). Their PA-099 control mappings (R29, R62) were
// migrated onto the surviving custom detectors in mappings.go.

// --- R37: AppLocker / WDAC heuristic ---

type R37AppLockerHeuristicDetector struct{ audit.BaseDetector }

func NewR37AppLockerHeuristicDetector() *R37AppLockerHeuristicDetector {
	return &R37AppLockerHeuristicDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R37_APPLOCKER_NOT_ENFORCED", audit.CategoryCompliance)}
}
func (d *R37AppLockerHeuristicDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// AppLocker config lives in AppLockerPolicy.xml under SYSVOL — not parsed
	// today. As a coarse heuristic, look for any GPO whose displayName mentions
	// AppLocker, WDAC, SRP or Code Integrity. Absence = ANSSI R37 likely fail.
	hasHint := false
	for _, gpo := range data.GPOs {
		name := strings.ToLower(gpo.DisplayName)
		if strings.Contains(name, "applocker") || strings.Contains(name, "wdac") ||
			strings.Contains(name, "code integrity") || strings.Contains(name, "srp ") {
			hasHint = true
			break
		}
	}
	count := 0
	if !hasHint {
		count = 1
	}
	return wrapFinding(d, "ANSSI R37 — AppLocker / WDAC absent (heuristique GPO)",
		"ANSSI R37 requires application allow-listing (AppLocker, WDAC, or equivalent). HEURISTIC ONLY: no GPO display name mentions AppLocker / WDAC / Code Integrity / SRP. The actual policy quality (XML rules) is not inspected by this detector.",
		types.SeverityMedium, count, nil)
}

// --- R38: Advanced Audit Policy enabled ---

type R38AdvancedAuditDetector struct{ audit.BaseDetector }

func NewR38AdvancedAuditDetector() *R38AdvancedAuditDetector {
	return &R38AdvancedAuditDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R38_ADVANCED_AUDIT_NOT_ENABLED", audit.CategoryCompliance)}
}
func (d *R38AdvancedAuditDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Heuristic: at least one GPO must enable Account Logon, Account Mgmt,
	// DS Access, Logon Events AND Object Access in EventAudit (subcategory
	// equivalents are below in audit.csv but we use the older [Event Audit]
	// section as a proxy).
	allEnabled := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.EventAudit == nil {
			continue
		}
		ea := p.EventAudit
		if ea.AuditAccountLogon >= 1 && ea.AuditAccountManage >= 1 &&
			ea.AuditDSAccess >= 1 && ea.AuditLogonEvents >= 1 && ea.AuditObjectAccess >= 1 {
			allEnabled = true
			break
		}
	}
	count := 0
	if !allEnabled {
		count = 1
	}
	return wrapFinding(d, "ANSSI R38 — Advanced Audit Policy incomplet",
		"ANSSI R38 requires the full Advanced Audit Policy (all 9 subcategories enabled for success+failure). Heuristic check on [Event Audit] coverage: at least one of Account Logon / Account Mgmt / DS Access / Logon Events / Object Access is missing.",
		types.SeverityHigh, count, nil)
}

// --- R39: Security Event log size + retention ---

type R39SecurityLogSizeDetector struct{ audit.BaseDetector }

func NewR39SecurityLogSizeDetector() *R39SecurityLogSizeDetector {
	return &R39SecurityLogSizeDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R39_SECURITY_LOG_TOO_SMALL", audit.CategoryCompliance)}
}
func (d *R39SecurityLogSizeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI recommends >= 1 GB Security log on DCs (1048576 KB).
	const minSizeKB = 1048576
	enoughSize := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.SecurityLogMaxSizeKB != nil && *p.RegistrySettings.SecurityLogMaxSizeKB >= minSizeKB {
			enoughSize = true
			break
		}
	}
	count := 0
	if !enoughSize {
		count = 1
	}
	return wrapFinding(d, "ANSSI R39 — Security event log < 1 GB",
		"ANSSI R39 requires the Security event log to be at least 1 GB on Domain Controllers (default 20 MB rolls in seconds under heavy auth load, losing forensic evidence).",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewR37AppLockerHeuristicDetector())
	audit.MustRegister(NewR38AdvancedAuditDetector())
	audit.MustRegister(NewR39SecurityLogSizeDetector())
}
