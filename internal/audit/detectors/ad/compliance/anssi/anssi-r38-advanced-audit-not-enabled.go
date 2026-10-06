package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- Advanced Audit Policy enabled (real control: PA-099 R13, p.30) ---
//
// The detector ID below ("R38") is a legacy internal label predating the
// v3.1.14 remap to official PA-099 R-codes (see mappings.go's package doc).
// Official PA-099 R38 (p.52) is about API secret risk handling, unrelated.
// mappings.go already tags this detector ID against its real control (R13).

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

func init() {
	audit.MustRegister(NewR38AdvancedAuditDetector())
}
