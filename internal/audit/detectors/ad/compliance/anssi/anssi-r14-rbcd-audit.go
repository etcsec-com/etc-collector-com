package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R14: RBCD (Resource-Based Constrained Delegation) sur un DC ---
//
// See r6_to_r15_lifecycle.go for the wrapFinding helper shared across this
// detector group; computersToEntities is defined in r15_r19_r40_tier0.go
// (same package).

type R14RBCDAuditDetector struct{ audit.BaseDetector }

func NewR14RBCDAuditDetector() *R14RBCDAuditDetector {
	return &R14RBCDAuditDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R14_RBCD_AUDIT", audit.CategoryCompliance)}
}
func (d *R14RBCDAuditDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit): the real R14 is "Détecter
	// automatiquement les potentiels incidents de sécurité" (p.31) -
	// unrelated to RBCD. RBCD is actually covered by R65 (p.90-91,
	// "Traiter les risques inhérents aux délégations Kerberos"), whose 4th
	// cumulative condition is: "la configuration de délégations contraintes
	// basées sur les ressources soit prohibée sur des services du Tier 0
	// depuis toute autre zone de confiance" - i.e. RBCD is a problem
	// specifically when its TARGET is a Tier 0 resource. Domain controllers
	// are the one Tier 0 asset always identifiable from collected data, so
	// this detector is scoped to RBCD configured on a DC rather than "any
	// RBCD anywhere" (the previous, much broader proxy). RBCD on non-DC
	// Tier 0 assets (PKI, backup, ADFS, …) is not covered here - the
	// collector has no general Tier 0 inventory to check against.
	dcDNs := make(map[string]bool, len(data.DomainControllers))
	for _, dc := range data.DomainControllers {
		dcDNs[strings.ToLower(dc.DN)] = true
	}
	var affected []types.Computer
	for _, c := range data.Computers {
		if len(c.AllowedToActOnBehalfOfOtherIdentity) == 0 {
			continue
		}
		if dcDNs[strings.ToLower(c.DN)] {
			affected = append(affected, c)
		}
	}
	entities := computersToEntities(affected, data.IncludeDetails)
	return wrapFinding(d, "ANSSI PA-099 R65 - RBCD configurée sur un contrôleur de domaine",
		"ANSSI PA-099 R65 (p.90-91) prohibits resource-based constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) configured on a Tier 0 service from any other trust zone. This detector checks the one Tier 0 asset class always identifiable from collected data - domain controllers; RBCD on other Tier 0 assets is not covered.",
		types.SeverityHigh, len(affected), entities)
}

func init() {
	audit.MustRegister(NewR14RBCDAuditDetector())
}
