package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R33: No permissive external trust ---
//
// See r28_to_r33_trusts.go for the isOutgoing helper shared across this
// group.

type R33ExternalTrustPermissiveDetector struct{ audit.BaseDetector }

func NewR33ExternalTrustPermissiveDetector() *R33ExternalTrustPermissiveDetector {
	return &R33ExternalTrustPermissiveDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R33_EXTERNAL_TRUST_PERMISSIVE", audit.CategoryCompliance)}
}
func (d *R33ExternalTrustPermissiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit): no single R-number states an
	// "external trust is permissive if EITHER control is missing" rule. The
	// real R33 is unrelated (scheduled-task/service-account secrets,
	// p.50-51). The two relevant controls are R24 (p.41, SID
	// filtering/quarantine - the primary hardening for outgoing extra-forest
	// domain trusts) and R25+ (p.42, Selective Authentication) - and R24's
	// own text frames R25+ as a compensating FALLBACK to apply "à défaut"
	// (failing) full R24 compliance, not as an independently-required
	// second layer: "À défaut, appliquer la recommandation R25+ permet
	// d'atténuer le risque de sécurité que représente un filtrage
	// insuffisant". So either control present is an acceptable mitigation;
	// the previous OR-trigger (flag if EITHER is missing, i.e. require BOTH
	// to be compliant) was stricter than the source. Scope narrowed to
	// outgoing trusts per R24/R25+'s own "sortantes" wording.
	count := 0
	for _, t := range data.Trusts {
		if !strings.EqualFold(t.TrustType, "External") {
			continue
		}
		if !isOutgoing(t) {
			continue
		}
		if !t.SelectiveAuth && !t.SIDFiltering {
			count++
		}
	}
	return wrapFinding(d, "ANSSI PA-099 R24/R25+ - Trust externe sortant sans aucune protection (ni quarantaine, ni authentification sélective)",
		"An outgoing external trust is permissive when it has NEITHER of ANSSI PA-099's two mitigations for extra-forest trust risk: R24's quarantine/SID filtering (p.41, primary) or R25+'s Selective Authentication (p.42, compensating fallback \"à défaut\" of R24). Per R24's own text, either one present is an acceptable mitigation.",
		types.SeverityHigh, count, nil)
}

func init() {
	audit.MustRegister(NewR33ExternalTrustPermissiveDetector())
}
