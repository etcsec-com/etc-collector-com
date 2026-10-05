package hds

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- HDS - Traçabilité des accès aux données de santé ---

type HDS54LogAccessHealthDetector struct{ audit.BaseDetector }

func NewHDS54LogAccessHealthDetector() *HDS54LogAccessHealthDetector {
	return &HDS54LogAccessHealthDetector{BaseDetector: audit.NewBaseDetector("HDS_5_4_LOG_ACCESS_TO_HEALTH_DATA", audit.CategoryCompliance)}
}
func (d *HDS54LogAccessHealthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Use the parsed EventAudit struct (audit.GPOPolicy.EventAudit) - value 3
	// = Both (Success+Failure), value 1 = Success only, value 2 = Failure
	// only. HDS expects Both - the old ">= 1" threshold accepted a
	// Success-only or Failure-only GPO as satisfying this, silently
	// producing false negatives on a domain that audits only successes (or
	// only failures) rather than both, contradicting the finding's own
	// description below. Fixed to require the Both value exactly.
	hasObjectAccessAudit := false
	for _, p := range data.GPOPolicies {
		if p != nil && p.EventAudit != nil && p.EventAudit.AuditObjectAccess >= 3 {
			hasObjectAccessAudit = true
			break
		}
	}
	count := 0
	if !hasObjectAccessAudit && len(data.GPOPolicies) > 0 {
		count = 1
	}
	return wrap(d, "HDS - Audit Object Access non configuré (Success et Failure)",
		"Traceability of access to health data is a standard expectation of HDS-certified environments. Référentiel HDS Exigences V1.1.20221027 does not set this out as a specific numbered chapter-5 requirement (chapter 5 covers generic ISMS process clauses 5.4-5.10; the closest related mentions are the risk-factor list in §5.6.1.2 and the audit obligation in §5.9.2, neither of which mandates this specific GPO setting). No GPO enables 'Audit Object Access' for both Success and Failure, leaving file-level access logging incomplete.",
		types.SeverityHigh, count)
}

func init() {
	audit.MustRegister(NewHDS54LogAccessHealthDetector())
}
