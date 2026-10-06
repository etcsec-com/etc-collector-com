package anssi

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R49 + R50: management agents and threat protection categorization ---
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf

// mgmtAgentMarkers identifies common centralized management endpoints by
// hostname or OS string. These should live in a dedicated tier (Tier 0 or
// Tier 1 depending on scope) per ANSSI R49/R50.
var mgmtAgentMarkers = []string{
	"sccm", "configmgr", "wsus", "mecm",
	"defender", "atp", "mdatp",
	"intune",
	"jamf",
	"ansible", "salt",
	"puppet", "chef",
	"tanium",
	"bigfix",
	"crowdstrike", "carbonblack", "sentinelone",
}

type R49R50MgmtCategorizationDetector struct{ audit.BaseDetector }

func NewR49R50MgmtCategorizationDetector() *R49R50MgmtCategorizationDetector {
	return &R49R50MgmtCategorizationDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R49_R50_MGMT_CATEGORIZATION", audit.CategoryCompliance),
	}
}

func (d *R49R50MgmtCategorizationDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	// v3.1.19 - set of explicit mgmt-system DNs from tier0_groups.yaml.
	customMgmt := map[string]bool{}
	if data.Tier0Config != nil {
		for _, dn := range data.Tier0Config.MgmtSystems {
			customMgmt[strings.ToLower(strings.TrimSpace(dn))] = true
		}
	}

	var unsorted []types.Computer
	for _, c := range data.Computers {
		host := strings.ToLower(c.SAMAccountName + " " + c.DNSHostName + " " + c.Description + " " + c.OperatingSystem)
		matches := customMgmt[strings.ToLower(c.DN)]
		if !matches {
			for _, m := range mgmtAgentMarkers {
				if strings.Contains(host, m) {
					matches = true
					break
				}
			}
		}
		if !matches {
			continue
		}
		// Flag if the computer DN does not contain a Tier-bearing OU marker.
		dn := strings.ToLower(c.DN)
		if strings.Contains(dn, "ou=tier0") || strings.Contains(dn, "ou=tier-0") ||
			strings.Contains(dn, "ou=tier1") || strings.Contains(dn, "ou=tier-1") ||
			strings.Contains(dn, "ou=admin") || strings.Contains(dn, "ou=mgmt") ||
			strings.Contains(dn, "ou=management") {
			continue
		}
		unsorted = append(unsorted, c)
	}
	if len(unsorted) == 0 {
		return nil
	}
	return wrapFinding(d, "ANSSI R49+R50 - Management agents not categorized into a dedicated Tier OU",
		fmt.Sprintf("%d computer(s) match centralized-management heuristics (SCCM/WSUS/Defender/Intune/...) but live outside any Tier 0/Tier 1/admin OU. ", len(unsorted))+
			"ANSSI R49 (p.62-63) + R50 (p.64) require categorization of management infrastructure: place these systems into a dedicated OU and apply the corresponding tier-segregated GPOs/ACLs. "+
			"HEURISTIC ONLY, on both signals: matching is by hostname/OS/description keyword and by an OU-name marker, an architectural control that isn't literally encoded anywhere in AD. A real management server with none of the mgmtAgentMarkers substrings in its name/description (custom or renamed product) is a false negative - R49/R50 do not fire for it even if it's genuinely miscategorized. Conversely, a correctly-tiered management server whose OU simply doesn't contain a recognized tier-name marker (e.g. a customer's own naming convention) is a false positive - flagged here despite being properly segregated in practice.",
		types.SeverityMedium, len(unsorted), computersToEntities(unsorted, data.IncludeDetails))
}

func init() {
	audit.MustRegister(NewR49R50MgmtCategorizationDetector())
}
