package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R56/R57: RODC deployed - Tier 0 groups missing from the deny-replication list ---
//
// "R15.1" never existed as PA-099 sub-reco numbering (see
// anssi-r29-1-forest-trust-no-selective-auth.go's note - PA-099 has no
// dotted sub-recommendation numbering at all). mappings.go already tags
// this detector ID against the real controls: R56 (p.71, "Déployer des
// RODC lorsque la sécurité physique n'est pas assurée") and R57 (p.72,
// "Appliquer les recommandations de sécurisation des RODC").
//
// The previous implementation flagged an EMPTY "Allowed RODC Password
// Replication Group" as non-compliant. That is backwards: R57's actual text
// says only site-local Tier 2 accounts should ever appear in that allow
// list, and an empty allow list is the safe default (nothing is cached) -
// not a violation of anything R56/R57 say. What R57 DOES require, textually
// (first bullet, p.72): "tous les comptes et groupes du Tier 0 ... doivent
// figurer dans la liste des comptes qui ne sont pas autorisés à être
// répliqués" - i.e. Tier 0 groups must explicitly appear in the deny list
// (msDS-NeverRevealGroup, default-populated via the builtin "Denied RODC
// Password Replication Group"). That's what this detector now checks. It is
// complementary to, not a duplicate of, ANSSI_R15_2_T0_ADMIN_REPLICATED_TO_RODC
// (which checks the allow list) and of the empirical
// RODC_PRIVILEGED_CACHING detector (which checks msDS-RevealedList, i.e.
// credentials already exposed in practice).

type R151RODCNoAllowedReplDetector struct{ audit.BaseDetector }

func NewR151RODCNoAllowedReplDetector() *R151RODCNoAllowedReplDetector {
	return &R151RODCNoAllowedReplDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R15_1_RODC_NO_ALLOWED_REPL", audit.CategoryCompliance)}
}

// tier0DeniedGroupNames are the built-in Tier 0 groups R57 (p.72) requires
// to appear in the RODC deny-replication list.
var tier0DeniedGroupNames = []string{"domain admins", "enterprise admins", "schema admins"}

func (d *R151RODCNoAllowedReplDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Only emit if at least one RODC exists in the domain.
	hasRODC := false
	for _, c := range data.Computers {
		if c.IsRODC {
			hasRODC = true
			break
		}
	}
	if !hasRODC {
		return wrapFinding(d, "ANSSI R56/R57 - N/A (pas de RODC déployé)",
			"ANSSI R56/R57 only apply when at least one RODC is present in the domain. None detected.",
			types.SeverityInfo, 0, nil)
	}

	denyMembers := map[string]bool{}
	for _, g := range data.Groups {
		if strings.EqualFold(g.SAMAccountName, "Denied RODC Password Replication Group") {
			for _, m := range g.Members {
				denyMembers[strings.ToLower(m)] = true
			}
		}
	}
	var missing []string
	for _, t0name := range tier0DeniedGroupNames {
		found := false
		for m := range denyMembers {
			if strings.Contains(m, t0name) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, t0name)
		}
	}

	if len(missing) == 0 {
		return wrapFinding(d, "ANSSI R56/R57 - Groupes Tier 0 présents dans la liste de refus de réplication RODC",
			"ANSSI R57 (p.72) requires every Tier 0 account/group to appear in the RODC deny-replication list. Domain Admins, Enterprise Admins and Schema Admins are all present.",
			types.SeverityMedium, 0, nil)
	}
	return wrapFinding(d, "ANSSI R56/R57 - Groupe(s) Tier 0 absents de la liste de refus de réplication RODC",
		"ANSSI R57 (p.72) requires every Tier 0 account/group to appear in the RODC deny-replication list (msDS-NeverRevealGroup, default-populated via the builtin 'Denied RODC Password Replication Group'), as defense-in-depth against a Tier 0 credential ever being cached on a physically-exposed RODC. "+
			fmt.Sprintf("Missing from that deny list: %s.", strings.Join(missing, ", ")),
		types.SeverityMedium, len(missing), nil)
}

func init() {
	audit.MustRegister(NewR151RODCNoAllowedReplDetector())
}
