package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-PA-099 R15 - domain/forest functional level below ANSSI baseline.
//
// Auditable from LDAP only. R15: Augmenter les niveaux fonctionnels des
// domaines et des forêts AD.
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf

// minFunctionalLevel is the lowest msDS-Behavior-Version value R15 (p.33)
// itself names as its floor: "Le niveau de fonctionnalité 6 (Windows
// Serveur 2012R2) est le minimum requis pour mettre en œuvre les
// recommandations de ce guide." Level 7 (Windows Server 2016) unlocks
// further benefits the guide separately describes (smart card account
// security improvements, PIM/PAM forest trusts) but R15's own text sets
// the required floor at 6, not 7 - the previous value here (7) was
// stricter than the source and would flag a 2012R2-level domain, which R15
// itself calls sufficient, as non-compliant.
const minFunctionalLevel = 6 // Windows Server 2012 R2

type R15FunctionalLevelDetector struct{ audit.BaseDetector }

func NewR15FunctionalLevelDetector() *R15FunctionalLevelDetector {
	return &R15FunctionalLevelDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R15_LOW_FUNCTIONAL_LEVEL", audit.CategoryCompliance),
	}
}

func (d *R15FunctionalLevelDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return nil
	}
	di := data.DomainInfo

	domLow := di.FunctionalLevelInt > 0 && di.FunctionalLevelInt < minFunctionalLevel
	forestLow := di.ForestFunctionalLevelInt > 0 && di.ForestFunctionalLevelInt < minFunctionalLevel
	if !domLow && !forestLow {
		return nil
	}

	parts := []string{}
	if domLow {
		parts = append(parts, fmt.Sprintf("domain functional level = %d (%s)", di.FunctionalLevelInt, di.FunctionalLevel))
	}
	if forestLow {
		parts = append(parts, fmt.Sprintf("forest functional level = %d (%s)", di.ForestFunctionalLevelInt, di.ForestFunctionalLevel))
	}

	return wrapFindingWithRepro(d, "ANSSI R15 - AD functional level below required baseline",
		"ANSSI R15 (p.33) states Windows Server 2012 R2 (msDS-Behavior-Version=6) is the minimum functional level required to implement the guide's recommendations; higher levels (e.g. 7 / Windows Server 2016) unlock further benefits (smart card account security, PIM/PAM forest trusts) but are not R15's floor. Current state: "+strings.Join(parts, "; ")+".",
		types.SeverityHigh, 1, nil,
		&types.FindingReproducibility{
			LDAPBaseDN: di.DomainDN,
			LDAPFilter: "(objectClass=domain)",
			LDAPAttrs:  []string{"msDS-Behavior-Version"},
			Notes:      "Compare msDS-Behavior-Version on the domain root and on CN=Partitions,CN=Configuration. Both must be ≥ 7 (Windows Server 2016).",
		})
}

func init() {
	audit.MustRegister(NewR15FunctionalLevelDetector())
}
