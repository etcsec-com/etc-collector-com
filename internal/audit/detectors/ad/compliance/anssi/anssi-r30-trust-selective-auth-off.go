package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R30: Trust Selective Authentication ---
//
// See r28_to_r33_trusts.go for the isExternalOrForest/isOutgoing helpers
// shared across this group.

type R30TrustSelectiveAuthDetector struct{ audit.BaseDetector }

func NewR30TrustSelectiveAuthDetector() *R30TrustSelectiveAuthDetector {
	return &R30TrustSelectiveAuthDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R30_TRUST_SELECTIVE_AUTH_OFF", audit.CategoryCompliance)}
}
func (d *R30TrustSelectiveAuthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit) R25+ (p.42), "Utiliser des
	// relations d'approbation sortantes avec authentification sélective":
	// applies to OUTGOING extra-forest trusts only ("relations d'approbation
	// SORTANTES extraforêt"), via the CROSS_ORGANIZATION attribute - exactly
	// types.Trust.SelectiveAuth. (The real R30/R30- in PA-099 is unrelated:
	// LAPS / local-admin-password rotation, p.47-48.) The previous version
	// never checked trust direction; an inbound-only trust is out of R25+'s
	// stated scope.
	count := 0
	for _, t := range data.Trusts {
		if isExternalOrForest(t) && isOutgoing(t) && !t.SelectiveAuth {
			count++
		}
	}
	return wrapFinding(d, "ANSSI PA-099 R25+ - Trust extraforêt sortant sans authentification sélective",
		"ANSSI PA-099 R25+ (p.42) recommends outgoing extra-forest trusts use Selective Authentication (CROSS_ORGANIZATION) so principals from the trusted domain can only authenticate to resources explicitly granted 'Allowed to authenticate'.",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewR30TrustSelectiveAuthDetector())
}
