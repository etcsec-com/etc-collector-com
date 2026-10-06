package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R86: Admin forest segregation ---

type R86AdminForestSegregationDetector struct{ audit.BaseDetector }

func NewR86AdminForestSegregationDetector() *R86AdminForestSegregationDetector {
	return &R86AdminForestSegregationDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R86_ADMIN_FOREST_SEGREGATION", audit.CategoryCompliance),
	}
}

// adminForestNameMarkers identifies trusts whose target is likely an
// administration forest (ESAE / Red Forest / PAW forest).
//
// Bare "red" and "t0" were removed - both are common English-word/
// abbreviation substrings with a high false-positive rate (e.g. "red"
// matches "shared.corp.local" or "credentials.corp.local"; "t0" matches
// "test01.corp.local" via its "st0" substring). This heuristic was never
// observed to fire in practice, so the false-positive risk was untested;
// the replacements below require the Red-Forest / Tier-0 token to appear as
// a more distinctive, delimited label instead of a bare 2-3 letter substring.
var adminForestNameMarkers = []string{"admin", "esae", "redforest", "red-forest", "paw", "tier0", "tier-0", "-t0", "t0-"}

func (d *R86AdminForestSegregationDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if len(data.Trusts) == 0 {
		return nil
	}
	// v3.1.19 - extra admin-forest DNS suffixes from tier0_groups.yaml.
	customDNS := []string{}
	if data.Tier0Config != nil {
		for _, dn := range data.Tier0Config.AdminForestDNS {
			if d := strings.ToLower(strings.TrimSpace(dn)); d != "" {
				customDNS = append(customDNS, d)
			}
		}
	}

	var weak []types.Trust
	for _, t := range data.Trusts {
		name := strings.ToLower(t.TargetDomain)
		isAdminForest := false
		for _, m := range adminForestNameMarkers {
			if strings.Contains(name, m) {
				isAdminForest = true
				break
			}
		}
		if !isAdminForest {
			for _, dns := range customDNS {
				if strings.Contains(name, dns) {
					isAdminForest = true
					break
				}
			}
		}
		if !isAdminForest {
			continue
		}
		// Hardening required: SID filtering ON + selective auth ON + AES allowed
		if !t.SIDFiltering || !t.SelectiveAuth {
			weak = append(weak, t)
		}
	}
	if len(weak) == 0 {
		return nil
	}
	var entities []types.AffectedEntity
	if data.IncludeDetails {
		for _, t := range weak {
			entities = append(entities, types.AffectedEntity{Type: "trust", Name: t.TargetDomain})
		}
	}
	return wrapFinding(d, "ANSSI R86 - Administration forest trust not properly segregated",
		fmt.Sprintf("%d trust(s) target what looks like an administration forest (name contains %s) but lack SID filtering and/or selective authentication. ",
			len(weak), strings.Join(adminForestNameMarkers, "/"))+
			"ANSSI R86 (p.116) requires segregation of any administration forest deployed, applying section 3.2.3's outbound-trust hardening (R24, p.40) to the relation between the admin forest and the forests it administers: forest-type trusts must not use SID history (no TREAT_AS_EXTERNAL), external/domain-type trusts must be quarantined (QUARANTINED_DOMAIN), plus selective authentication. CAVEAT: this detector only has a single generic SIDFiltering boolean per trust, not the underlying trust-attribute bitmask - R24 prescribes a DIFFERENT bit per trust type (TREAT_AS_EXTERNAL for Forest trusts vs. QUARANTINED_DOMAIN for External trusts). If SIDFiltering is wired to only one of those bits, a correctly-hardened trust of the other type could be a false positive here; this has never been observed to fire, so the mapping is unverified.",
		types.SeverityHigh, len(weak), entities)
}

func init() {
	audit.MustRegister(NewR86AdminForestSegregationDetector())
}
