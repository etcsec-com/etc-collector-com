package privileged

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// BuiltinModifiedDetector checks for builtin groups with non-standard members
type BuiltinModifiedDetector struct {
	audit.BaseDetector
}

// NewBuiltinModifiedDetector creates a new detector
func NewBuiltinModifiedDetector() *BuiltinModifiedDetector {
	return &BuiltinModifiedDetector{
		BaseDetector: audit.NewBaseDetector("BUILTIN_MODIFIED", audit.CategoryGroups),
	}
}

// Builtin groups and their expected default members
var builtinDefaults = map[string][]string{
	"Administrators":                  {"Administrator", "Domain Admins", "Enterprise Admins"},
	"Users":                           {"Domain Users", "Authenticated Users", "INTERACTIVE"},
	"Guests":                          {"Guest", "Domain Guests"},
	"Remote Desktop Users":            {},
	"Network Configuration Operators": {},
	"Performance Monitor Users":       {},
	"Performance Log Users":           {},
	"Distributed COM Users":           {},
	"IIS_IUSRS":                       {},
	"Cryptographic Operators":         {},
	"Event Log Readers":               {},
	"Certificate Service DCOM Access": {},
}

var cnRegex = regexp.MustCompile(`(?i)CN=([^,]+)`)

// Detect executes the detection
func (d *BuiltinModifiedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group
	var affectedNames []string

	for _, group := range data.Groups {
		name := group.SAMAccountName

		// Check if it's a builtin group we monitor
		expectedMembers, isBuiltin := builtinDefaults[name]
		if !isBuiltin {
			continue
		}

		// Check for unexpected members
		hasUnexpectedMembers := false
		for _, memberDN := range group.Member {
			matches := cnRegex.FindStringSubmatch(memberDN)
			if len(matches) < 2 {
				continue
			}
			memberCN := matches[1]

			// Check if this member is in the expected list
			isExpected := false
			for _, exp := range expectedMembers {
				if strings.EqualFold(memberCN, exp) || strings.Contains(strings.ToLower(memberCN), strings.ToLower(exp)) {
					isExpected = true
					break
				}
			}
			if !isExpected {
				hasUnexpectedMembers = true
				break
			}
		}

		if hasUnexpectedMembers {
			affected = append(affected, group)
			affectedNames = append(affectedNames, name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Builtin Group Modified",
		Description: "Builtin groups contain non-standard members. This may indicate privilege escalation or backdoor access.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
		}
		finding.Details = map[string]interface{}{
			"groups":         affectedNames,
			"recommendation": "Review membership of builtin groups and remove unexpected members. Document any intentional additions.",
			"risk":           "Attackers often add accounts to builtin groups for persistent access.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewBuiltinModifiedDetector())
}
