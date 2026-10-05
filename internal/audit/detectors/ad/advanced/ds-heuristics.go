package advanced

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DsHeuristicsLDAPSecurityDetector checks dsHeuristics for insecure LDAP settings
type DsHeuristicsLDAPSecurityDetector struct {
	audit.BaseDetector
}

// NewDsHeuristicsLDAPSecurityDetector creates a new detector
func NewDsHeuristicsLDAPSecurityDetector() *DsHeuristicsLDAPSecurityDetector {
	return &DsHeuristicsLDAPSecurityDetector{
		BaseDetector: audit.NewBaseDetector("DS_HEURISTICS_LDAP_SECURITY", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *DsHeuristicsLDAPSecurityDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "dsHeuristics LDAP Security Weakened",
		Description: "The dsHeuristics attribute contains settings that weaken LDAP security. Position 7 (fLDAPBlockAnonOps) controls anonymous LDAP operations. When set to '2', anonymous LDAP operations are allowed, permitting unauthenticated enumeration of directory objects.",
		Count:       0,
	}

	if data.DomainInfo == nil || data.DomainInfo.DsHeuristics == "" {
		return []types.Finding{finding}
	}

	dsh := data.DomainInfo.DsHeuristics
	issues := []string{}

	// Position 6 (0-indexed) = 7th character = fLDAPBlockAnonOps.
	// [MS-ADTS]: dSHeuristics (character table, row 7 "fLDAPBlockAnonOps"):
	// "If this character is '2', then the fLDAPBlockAnonOps heuristic is
	// FALSE [i.e. anonymous LDAP operations are NOT blocked]; otherwise, the
	// fLDAPBlockAnonOps heuristic is TRUE [blocked]." The spec's own worked
	// example for *enabling* anonymous LDAP operations produces the string
	// "0000002" - a 7-character value whose 7th character is '2'. So '2'
	// means LESS secure (anonymous ops allowed), any other value (including
	// absent, which defaults to '0' at DS_BEHAVIOR_WIN2003+) means blocked.
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5
	if len(dsh) > 6 && dsh[6] == '2' {
		issues = append(issues, "Position 7 (fLDAPBlockAnonOps) is set to '2' - anonymous LDAP operations are allowed")
	}

	// Position 3 (0-indexed): fAllowAnonymousAccess
	// "2" = allow anonymous access (insecure for pre-Windows 2000 compat)
	if len(dsh) > 3 && string(dsh[3]) == "2" {
		issues = append(issues, "Position 3 (fAllowAnonymousAccess) is set to '2' - anonymous access explicitly allowed")
	}

	// Position 28 (0-indexed): LDAPAddAuthZVerifications (CVE-2021-42291 mitigation)
	// "1" = full enforcement (secure). "0" or missing = vulnerable
	if len(dsh) > 28 {
		if string(dsh[28]) != "1" {
			issues = append(issues, "Position 28 (LDAPAddAuthZVerifications) is not '1' - CVE-2021-42291 LDAP add not fully enforced")
		}
	} else {
		// dsHeuristics too short - position 28 defaults to 0 (vulnerable)
		issues = append(issues, "Position 28 (LDAPAddAuthZVerifications) is missing (defaults to 0) - CVE-2021-42291 LDAP add not enforced")
	}

	// Position 29 (0-indexed): LDAPOwnerModify (CVE-2021-42291 mitigation)
	// "1" = full enforcement (secure). "0" or missing = vulnerable
	if len(dsh) > 29 {
		if string(dsh[29]) != "1" {
			issues = append(issues, "Position 29 (LDAPOwnerModify) is not '1' - CVE-2021-42291 owner modification not fully enforced")
		}
	} else {
		issues = append(issues, "Position 29 (LDAPOwnerModify) is missing (defaults to 0) - CVE-2021-42291 owner modification not enforced")
	}

	finding.Count = len(issues)
	if len(issues) > 0 {
		finding.Details = map[string]interface{}{
			"dsHeuristics": dsh,
			"issues":       issues,
		}
		if data.IncludeDetails {
			entities := make([]types.AffectedEntity, len(issues))
			for i, issue := range issues {
				entities[i] = types.AffectedEntity{Type: "config", Name: issue}
			}
			finding.AffectedEntities = entities
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDsHeuristicsLDAPSecurityDetector())
}
