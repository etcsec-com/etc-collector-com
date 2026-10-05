package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R25+: Outgoing forest trust without selective auth ---
//
// "R29.1" never existed (PA-099 has no dotted sub-recommendation
// numbering). mappings.go already tags this ID against the real control,
// R25+ (p.41-42, "Utiliser des relations d'approbation sortantes avec
// authentification sélective"). R25+'s text is explicitly scoped to
// OUTGOING ("sortantes") extra-forest trusts - an inbound-only forest trust
// has no "sortante" component and is out of R25+'s scope. The previous
// implementation counted every non-selective-auth forest trust regardless
// of direction, which would flag an inbound-only trust for a control that
// doesn't apply to it.

type R291ForestTrustNoSelAuthDetector struct{ audit.BaseDetector }

func NewR291ForestTrustNoSelAuthDetector() *R291ForestTrustNoSelAuthDetector {
	return &R291ForestTrustNoSelAuthDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R29_1_FOREST_TRUST_NO_SELECTIVE_AUTH", audit.CategoryCompliance)}
}

// hasOutboundComponent reports whether a trust carries an outgoing
// authentication path - Outbound or Bidirectional. Inbound-only trusts have
// no outbound leg and are out of R25+'s scope.
func hasOutboundComponent(t types.Trust) bool {
	if t.TrustDirectionInt == 2 || t.TrustDirectionInt == 3 {
		return true
	}
	return strings.EqualFold(t.TrustDirection, "Outbound") || strings.EqualFold(t.TrustDirection, "Bidirectional")
}

func (d *R291ForestTrustNoSelAuthDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	for _, t := range data.Trusts {
		if !strings.EqualFold(t.TrustType, "Forest") {
			continue
		}
		if !hasOutboundComponent(t) {
			continue // R25+ scopes outgoing trusts only
		}
		if !t.SelectiveAuth {
			count++
		}
	}
	return wrapFinding(d, "ANSSI R25+ - Trust forêt sortant sans Selective Authentication",
		"ANSSI R25+ (p.41-42) requires outgoing extra-forest trusts to use Selective Authentication. Scoped to trusts with an outbound component (Outbound or Bidirectional); an inbound-only forest trust has no outbound leg and is out of R25+'s scope.",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewR291ForestTrustNoSelAuthDetector())
}
