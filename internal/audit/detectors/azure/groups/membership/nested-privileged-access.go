package membership

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NestedPrivilegedDetector checks for nested groups with privileged access
type NestedPrivilegedDetector struct {
	audit.BaseDetector
}

// NewNestedPrivilegedDetector creates a new detector
func NewNestedPrivilegedDetector() *NestedPrivilegedDetector {
	return &NestedPrivilegedDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_NESTED_PRIVILEGED", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *NestedPrivilegedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	// Groups with AdminCount == true and nested in other groups
	for _, group := range data.Groups {
		if group.AdminCount && len(group.MemberOf) > 0 {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Nested Groups with Privileged Access",
		Description: "Groups nested in other privileged groups create indirect privilege escalation paths.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNestedPrivilegedDetector())
}
