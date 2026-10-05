package hds

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- HDS - Chiffrement des données en transit (LDAPS enforced everywhere) ---

type HDS52TLSEnforcedDetector struct{ audit.BaseDetector }

func NewHDS52TLSEnforcedDetector() *HDS52TLSEnforcedDetector {
	return &HDS52TLSEnforcedDetector{BaseDetector: audit.NewBaseDetector("HDS_5_2_TLS_NOT_ENFORCED", audit.CategoryCompliance)}
}
func (d *HDS52TLSEnforcedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// LDAP signing / channel binding aren't exposed as DomainInfo fields in
	// the current collector. Emit an informational hint pointing to the
	// LDAPS connection diagnostic the daemon performs at startup (TLSDiag).
	count := 1 // always emit so it shows up in HDS report scaffolding
	return wrap(d, "HDS - Vérifier le chiffrement de tout le trafic AD",
		"Encryption of data in transit is a standard expectation of HDS-certified environments. Référentiel HDS Exigences V1.1.20221027 does not set this out as a specific numbered chapter-5 requirement - the only related mention anywhere in the document is Annexe 2's SecNumCloud cross-reference matrix, where ISO 27001 Annex A control 5.14 'Transferts d'information' maps to SecNumCloud §10.2 'Chiffrement des flux' (a mapping-matrix entry, not an HDS exigence). Verify LDAPS-only on every DC (port 389 disabled or signing-required) and that LDAP_SIGNING / channel binding GPOs are enforced. Use 'etc-collector audit ad' TLSDiag output as evidence.",
		types.SeverityInfo, count)
}

func init() {
	audit.MustRegister(NewHDS52TLSEnforcedDetector())
}
