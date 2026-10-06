package hds

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- HDS - Authentification forte (MFA partout pour accès aux données santé) ---
//
// Distinct from ANSSI R3 (which checks MFA on privileged accounts only): HDS
// certification expects MFA on every account that may touch health data,
// which we approximate as "every enabled non-service account".

type HDS514AuthForteDetector struct{ audit.BaseDetector }

func NewHDS514AuthForteDetector() *HDS514AuthForteDetector {
	return &HDS514AuthForteDetector{BaseDetector: audit.NewBaseDetector("HDS_5_1_4_STRONG_AUTH", audit.CategoryCompliance)}
}
func (d *HDS514AuthForteDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// MFA / smartcard enforcement is not observable from default AD attributes
	// in this collector; emit an informational reminder so the auditor cross-
	// checks via Entra CA, Conditional Access, or third-party MFA tooling.
	//
	// Previously gated on len(data.Users) > 0 - that's a test that
	// user data was collected at all, not a measurement of authentication
	// strength (any real audit has users, so this was functionally always
	// "1" while pretending to be data-driven). Made unconditional, matching
	// the honest "standing reminder" pattern used by the other detectors in
	// this package (and by industry.AuditLogRetentionDetector /
	// DataClassificationDetector for the same "cannot verify via LDAP"
	// shape of advisory).
	return wrap(d, "HDS - Authentification forte à vérifier hors AD",
		"Strong authentication for accounts accessing health data is a standard expectation of HDS-certified environments. Référentiel HDS Exigences V1.1.20221027 does not set this out as a specific numbered requirement (its chapter 5 covers ISMS governance/process clauses 5.4-5.10, not per-topic technical controls). AD alone cannot confirm MFA enforcement; cross-check with Entra Conditional Access or third-party MFA.",
		types.SeverityInfo, 1)
}

func init() {
	audit.MustRegister(NewHDS514AuthForteDetector())
}
