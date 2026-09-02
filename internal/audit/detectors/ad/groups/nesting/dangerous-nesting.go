package nesting

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DangerousNestingDetector checks for sensitive groups nested in less sensitive groups
type DangerousNestingDetector struct {
	audit.BaseDetector
}

// NewDangerousNestingDetector creates a new detector
func NewDangerousNestingDetector() *DangerousNestingDetector {
	return &DangerousNestingDetector{
		BaseDetector: audit.NewBaseDetector("DANGEROUS_GROUP_NESTING", audit.CategoryGroups),
	}
}

var protectedGroups = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Account Operators",
	"Backup Operators",
	"Server Operators",
	"Print Operators",
}

// Detect executes the detection
func (d *DangerousNestingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	for _, group := range data.Groups {
		if len(group.MemberOf) == 0 {
			continue
		}

		// Check if this is a protected group
		isProtected := false
		for _, pg := range protectedGroups {
			if strings.Contains(group.DistinguishedName, "CN="+pg) {
				isProtected = true
				break
			}
		}
		if !isProtected {
			continue
		}

		// Check if it's nested in a non-protected group
		hasUnexpectedNesting := false
		for _, parentDN := range group.MemberOf {
			isParentProtected := false
			for _, pg := range protectedGroups {
				if strings.Contains(parentDN, "CN="+pg) {
					isParentProtected = true
					break
				}
			}
			if !isParentProtected {
				hasUnexpectedNesting = true
				break
			}
		}

		if hasUnexpectedNesting {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Dangerous Group Nesting",
		Description: "Sensitive group nested in less sensitive group. Unintended privilege escalation path.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousNestingDetector())
}
