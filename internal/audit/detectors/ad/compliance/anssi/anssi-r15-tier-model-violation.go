package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R15: Comptes admin hors OU Tier 0 dédiée ---
//
// See r6_to_r15_lifecycle.go for the wrapFinding helper shared across this
// detector group.

type R15TierModelViolationDetector struct{ audit.BaseDetector }

func NewR15TierModelViolationDetector() *R15TierModelViolationDetector {
	return &R15TierModelViolationDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R15_TIER_MODEL_VIOLATION", audit.CategoryCompliance)}
}
func (d *R15TierModelViolationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit): the real R15 is "Augmenter les
	// niveaux fonctionnels des domaines et des forêts AD" (p.34) - DFL/FFL,
	// unrelated to tier isolation. The dedicated-OU requirement this
	// detector actually implements is R58 (p.73-74, "Créer une unité
	// organisationnelle réunissant les objets du Tier 0"): a Tier 0 OU near
	// the domain root containing Tier 0 objects, including a users sub-OU
	// for Tier 0 admin accounts - R8 (p.25) states the broader "cloisonner
	// l'administration de chaque Tier" principle behind it. Without session
	// logs we use a structural proxy: privileged users (AdminCount=1)
	// located outside a dedicated admin OU. R58 does not mandate a specific
	// OU name, so this remains a naming heuristic (OU=Tier0/OU=Admin).
	var count int
	for _, u := range data.Users {
		if !u.AdminCount || u.Disabled {
			continue
		}
		dn := strings.ToLower(u.DN)
		if strings.Contains(dn, "cn=users,") && !strings.Contains(dn, "ou=tier0") && !strings.Contains(dn, "ou=admin") {
			count++
		}
	}
	return wrapFinding(d, "ANSSI PA-099 R58 - Comptes admin hors OU Tier 0 dédiée",
		"ANSSI PA-099 R58 (p.73-74) requires a dedicated OU near the domain root for Tier 0 objects, including a sub-OU for Tier 0 admin accounts; R8 (p.25) states the underlying per-Tier administration segregation principle. Accounts still in the default CN=Users container break tier-aware GPO targeting.",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewR15TierModelViolationDetector())
}
