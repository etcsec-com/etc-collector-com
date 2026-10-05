package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- BP-039 R10: Credential Guard not deployed (presence) + R10*/R10** scope ---
// ANSSI_R35_CREDENTIAL_GUARD_OFF already covers the basic "Credential Guard
// off" case mapped to BP-039 R10. Here we add the scope variants R10* (sensitive
// workstations only) vs R10** (all workstations) - when CredGuard is enabled
// but only LsaCfgFlags=1 is set, scope is "sensitive only".
//
// See bp039_phase_c.go for the shared gpoSetsAtLeast/gpoMaxValue helpers.

type BP039CredGuardLimitedScopeDetector struct{ audit.BaseDetector }

func NewBP039CredGuardLimitedScopeDetector() *BP039CredGuardLimitedScopeDetector {
	return &BP039CredGuardLimitedScopeDetector{
		BaseDetector: audit.NewBaseDetector("BP039_CRED_GUARD_LIMITED_SCOPE", audit.CategoryCompliance),
	}
}

func (d *BP039CredGuardLimitedScopeDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// v3.1.18 - exact scope check via GPOLinks (was: count of GPOs).
	// R10**  = Credential Guard ON every workstation (= GPO linked at domain root).
	// R10*   = Credential Guard ON sensitive-only (= linked to Tier 0 OU(s)).
	// We fire if NO GPO with LsaCfgFlags>=1 is linked at the domain root.
	maxCG := gpoMaxValue(data, func(rs *audit.RegistrySettings) *int { return rs.LsaCfgFlags })
	if maxCG < 1 {
		return nil // not enabled at all → covered by R35 instead
	}
	domainDN := ""
	if data.DomainInfo != nil {
		domainDN = data.DomainInfo.DomainDN
	}
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		if p.RegistrySettings.LsaCfgFlags == nil || *p.RegistrySettings.LsaCfgFlags < 1 {
			continue
		}
		scope := helpers.ComputeGPOScope(data, p.GUID, domainDN)
		if scope.LinkedToDomain {
			return nil // R10** satisfied
		}
	}
	return wrapFinding(d, "ANSSI BP-039 R10** - Credential Guard scope appears limited",
		"ANSSI BP-039 R10** recommends Credential Guard on ALL workstations (R10* is the lower-bar variant for sensitive ones only). No GPO with LsaCfgFlags>=1 is linked at the domain root, so deployment is restricted to a subset of OUs. Link the Credential Guard GPO at the domain root for full coverage (defense in depth).",
		types.SeverityLow, 1, nil)
}

func init() {
	audit.MustRegister(NewBP039CredGuardLimitedScopeDetector())
}
