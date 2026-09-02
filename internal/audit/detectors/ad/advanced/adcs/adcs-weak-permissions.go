package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ADCSWeakPermissionsDetector detects weak permissions on ADCS objects
type ADCSWeakPermissionsDetector struct {
	audit.BaseDetector
}

// NewADCSWeakPermissionsDetector creates a new detector
func NewADCSWeakPermissionsDetector() *ADCSWeakPermissionsDetector {
	return &ADCSWeakPermissionsDetector{
		BaseDetector: audit.NewBaseDetector("ADCS_WEAK_PERMISSIONS", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *ADCSWeakPermissionsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string

	for _, t := range data.CertTemplates {
		// Check if template has weak ACLs allowing enrollment by non-admins
		if t.HasWeakEnrollmentACL || t.HasGenericAllPermission {
			name := t.Name
			if name == "" {
				name = t.DisplayName
			}
			affectedNames = append(affectedNames, name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ADCS Weak Permissions",
		Description: "Weak permissions on ADCS objects or certificate templates allow unauthorized enrollment.",
		Count:       len(affectedNames),
	}

	if data.IncludeDetails && len(affectedNames) > 0 {
		entities := make([]types.AffectedEntity, len(affectedNames))
		for i, name := range affectedNames {
			entities[i] = types.AffectedEntity{
				Type:           "certTemplate",
				SAMAccountName: name,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewADCSWeakPermissionsDetector())
}
