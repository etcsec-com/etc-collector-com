package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Windows hardening (DC-side) and audit policy.
//
// The detector IDs below ("R37"/"R38"/"R39") are legacy internal labels
// predating the v3.1.14 remap to official PA-099 R-codes (see mappings.go's
// package doc, and its migration note: "Re-mapped in v3.1.14 to use
// OFFICIAL ANSSI-PA-099 v1.0 R-codes ... instead of the internal R1-R39
// numbering used in v3.1.0-v3.1.13"). They collide with real, unrelated
// PA-099 R-codes: official R37 (p.51) is about weak/vulnerable Tier 0
// certificates (see r37_weak_certs.go - the ID collision is intentional
// there, ANSSI_R37_WEAK_CERT_TEMPLATES actually IS R37), official R38
// (p.52) is about API secret risk handling, and official R39 (p.53) is
// about physical access to Tier 0 secrets. None of the three official
// codes concern AppLocker, advanced audit policy, or event log size.
// mappings.go already tags these three detector IDs against their real
// controls (R11, R13, R13 respectively) - this file's Title/Description
// text below is corrected to match, since an auditor reading a finding
// titled "ANSSI R38" would reasonably go looking for R38 in PA-099 and
// find something unrelated.
//
// v3.1.21 dedup: R34 (LSA Protection, WDigest) and R35 (Credential Guard)
// removed - they checked the exact same registry keys as the pre-existing
// custom detectors (LSA_PROTECTION_DISABLED, WDIGEST_ENABLED,
// CREDENTIAL_GUARD_DISABLED). Their PA-099 control mappings (R29, R62) were
// migrated onto the surviving custom detectors in mappings.go.

// --- AppLocker / WDAC heuristic (real control: PA-099 R11, p.28) ---

type R37AppLockerHeuristicDetector struct{ audit.BaseDetector }

func NewR37AppLockerHeuristicDetector() *R37AppLockerHeuristicDetector {
	return &R37AppLockerHeuristicDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R37_APPLOCKER_NOT_ENFORCED", audit.CategoryCompliance)}
}
func (d *R37AppLockerHeuristicDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// AppLocker config lives in AppLockerPolicy.xml under SYSVOL - not parsed
	// today. As a coarse heuristic, look for any GPO whose displayName mentions
	// AppLocker, WDAC, SRP or Code Integrity. Absence = likely no allow-listing.
	//
	// This is a name-based heuristic with real, structural blind spots: a
	// GPO enforcing AppLocker/WDAC under an unrelated name (e.g. "Corp
	// Security Baseline") silences neither a true positive nor a true
	// negative correctly either way, and AppLockerPolicy.xml itself (the
	// actual rule content under SYSVOL) is never parsed, so policy quality
	// is never checked even when a hinting GPO exists.
	hasHint := false
	for _, gpo := range data.GPOs {
		name := strings.ToLower(gpo.DisplayName)
		if strings.Contains(name, "applocker") || strings.Contains(name, "wdac") ||
			strings.Contains(name, "code integrity") || strings.Contains(name, "srp") {
			hasHint = true
			break
		}
	}
	count := 0
	if !hasHint {
		count = 1
	}
	return wrapFinding(d, "AppLocker / WDAC absent (heuristique GPO)",
		"ANSSI PA-099 R11 (p.28) recommends applying system/software hardening measures that contribute to Tier isolation, which includes application allow-listing (AppLocker, WDAC, or equivalent). HEURISTIC ONLY: no GPO display name mentions AppLocker / WDAC / Code Integrity / SRP. The actual policy quality (XML rules under SYSVOL) is not inspected by this detector, and a hinting or non-hinting GPO name proves nothing about whether allow-listing is actually enforced.",
		types.SeverityMedium, count, nil)
}

// --- Advanced Audit Policy enabled (real control: PA-099 R13, p.30) ---

type R38AdvancedAuditDetector struct{ audit.BaseDetector }

func NewR38AdvancedAuditDetector() *R38AdvancedAuditDetector {
	return &R38AdvancedAuditDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R38_ADVANCED_AUDIT_NOT_ENABLED", audit.CategoryCompliance)}
}
func (d *R38AdvancedAuditDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	compliant := false
	for _, p := range data.GPOPolicies {
		if p == nil {
			continue
		}
		// Advanced Audit Policy Configuration (audit.csv) is the modern
		// mechanism Microsoft recommends over the legacy [Event Audit]
		// section - once used, Windows can be told to ignore [Event Audit]
		// entirely (SCENoApplyLegacyAuditPolicy). A domain managing its
		// audit policy exclusively through audit.csv would have an empty
		// [Event Audit] section on every GPO, which the previous
		// implementation (checking [Event Audit] only) would have flagged
		// as non-compliant despite being correctly configured through the
		// ANSSI-recommended mechanism - a structural false positive.
		if len(p.AdvancedAudit) > 0 {
			compliant = true
			break
		}
		if p.EventAudit == nil {
			continue
		}
		ea := p.EventAudit
		// Require success+failure (level 3) on all five categories, not
		// merely "some auditing" (level 1 = success-only would silence
		// this check while missing every failed-logon/failed-access event
		// R13's "événement pouvant signaler une tentative de contournement"
		// language cares about).
		if ea.AuditAccountLogon == 3 && ea.AuditAccountManage == 3 &&
			ea.AuditDSAccess == 3 && ea.AuditLogonEvents == 3 && ea.AuditObjectAccess == 3 {
			compliant = true
			break
		}
	}
	count := 0
	if !compliant {
		count = 1
	}
	return wrapFinding(d, "Advanced Audit Policy incomplet",
		"ANSSI PA-099 R13 (p.30) requires logging and centralizing security-relevant events, in particular anything that could signal an attempt to bypass Tier segregation or to move laterally. Checked via either the modern Advanced Audit Policy Configuration (audit.csv, present when any GPO's AdvancedAudit map is populated) or, as a fallback, the legacy [Event Audit] section requiring success+failure (level 3, not just level 1) on Account Logon / Account Mgmt / DS Access / Logon Events / Object Access. An audit policy applied purely through local security policy on each DC (outside any GPO) is not visible to either source.",
		types.SeverityHigh, count, nil)
}

// --- Security Event log size + retention (real control: PA-099 R13, p.30) ---

type R39SecurityLogSizeDetector struct{ audit.BaseDetector }

func NewR39SecurityLogSizeDetector() *R39SecurityLogSizeDetector {
	return &R39SecurityLogSizeDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R39_SECURITY_LOG_TOO_SMALL", audit.CategoryCompliance)}
}
func (d *R39SecurityLogSizeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI R13 (p.30) doesn't fix a byte threshold; 1 GB (Windows default
	// is 20 MB) is an etc-collector product benchmark large enough to
	// survive a heavy-auth-load rollover without losing forensic evidence.
	const minSizeKB = 1048576
	enoughSize := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.SecurityLogMaxSizeKB == nil || *p.RegistrySettings.SecurityLogMaxSizeKB < minSizeKB {
			continue
		}
		// The previous implementation accepted a large SecurityLogMaxSizeKB
		// from ANY GPO regardless of what it's linked to - a GPO setting
		// 1 GB but linked only to, say, an OU of file servers never
		// touches the Domain Controllers whose 20 MB default this check
		// exists to catch, so the check would go silent while every DC
		// stayed at the vulnerable default. Require the GPO to actually
		// reach the DCs.
		if gpoLinkedToDCs(p.GUID, data) {
			enoughSize = true
			break
		}
	}
	count := 0
	if !enoughSize {
		count = 1
	}
	return wrapFinding(d, "Security event log < 1 GB on Domain Controllers",
		"ANSSI PA-099 R13 (p.30) requires logging and centralizing security-relevant events, which a log that rolls over in minutes under heavy auth load defeats. No GPO both sets the Security event log to at least 1 GB (etc-collector product benchmark; Windows default is 20 MB) AND is linked (enabled, not disabled) to the Domain Controllers OU or the domain root - the only scopes that reliably reach Domain Controllers.",
		types.SeverityMedium, count, nil)
}

// gpoLinkedToDCs reports whether a GPO (identified by its GUID) has an
// enabled link to the Domain Controllers OU or the domain root. Uses the
// same GUID-substring-match convention as R59Tier0OUPoliciesDetector
// (phase_d_detectors.go) against GPOLink.GPOCN/GPOGuid.
func gpoLinkedToDCs(gpoGUID string, data *audit.DetectorData) bool {
	guid := strings.ToLower(strings.Trim(gpoGUID, "{}"))
	if guid == "" {
		return false
	}
	for _, link := range data.GPOLinks {
		if !link.LinkEnabled || link.Disabled {
			continue
		}
		ref := strings.ToLower(link.GPOCN)
		if ref == "" {
			ref = strings.ToLower(link.GPOGuid)
		}
		if !strings.Contains(ref, guid) {
			continue
		}
		target := strings.ToLower(link.LinkedTo)
		if strings.Contains(target, "ou=domain controllers") || strings.HasPrefix(target, "dc=") {
			return true
		}
	}
	return false
}

func init() {
	audit.MustRegister(NewR37AppLockerHeuristicDetector())
	audit.MustRegister(NewR38AdvancedAuditDetector())
	audit.MustRegister(NewR39SecurityLogSizeDetector())
}
