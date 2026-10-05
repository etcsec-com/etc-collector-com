package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R29: Trust SID filtering enabled on every external/forest trust ---
//
// See r28_to_r33_trusts.go for the isOutgoing helper shared across this
// group.

type R29TrustSIDFilteringDetector struct{ audit.BaseDetector }

func NewR29TrustSIDFilteringDetector() *R29TrustSIDFilteringDetector {
	return &R29TrustSIDFilteringDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R29_TRUST_SID_FILTERING_OFF", audit.CategoryCompliance)}
}
func (d *R29TrustSIDFilteringDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// ANSSI PA-099 (full-text source audit) R24 (p.41), "Durcir la
	// configuration des relations d'approbation AD sortantes extraforêt":
	// applies only to OUTGOING extra-forest trusts, and the mechanism
	// DIFFERS by trust type:
	//   - domain/external trust: harden by ADDING QUARANTINED_DOMAIN
	//     ("quarantine") - this is exactly types.Trust.SIDFiltering;
	//   - forest trust: harden by REMOVING TREAT_AS_EXTERNAL (SID history) -
	//     a different attribute the collector does not currently parse into
	//     types.Trust, so it cannot be checked here.
	// (The real R29 in PA-099 is unrelated: the general "reusable secrets
	// must not cross Tier boundaries" principle, p.46.) Scope is therefore
	// narrowed to what's both correct and measurable: outgoing external
	// (non-forest) trusts only.
	count := 0
	for _, t := range data.Trusts {
		if !strings.EqualFold(t.TrustType, "External") {
			continue
		}
		if !isOutgoing(t) {
			continue
		}
		if !t.SIDFiltering {
			count++
		}
	}
	return wrapFinding(d, "ANSSI PA-099 R24 - Trust externe sortant sans quarantaine (SID filtering)",
		"ANSSI PA-099 R24 (p.41) requires outgoing extra-forest DOMAIN (external) trusts to have the QUARANTINED_DOMAIN attribute (SID filtering / quarantine). KNOWN LIMITATION: R24's forest-trust hardening (removing TREAT_AS_EXTERNAL) is not checked here - that attribute is not currently collected - so forest trusts are excluded from this detector rather than checked against the wrong attribute.",
		types.SeverityHigh, count, nil)
}

func init() {
	audit.MustRegister(NewR29TrustSIDFilteringDetector())
}
