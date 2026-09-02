package high

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GpoToDADetector detects GPO modification paths to Domain Admin
type GpoToDADetector struct {
	audit.BaseDetector
}

// NewGpoToDADetector creates a new detector
func NewGpoToDADetector() *GpoToDADetector {
	return &GpoToDADetector{
		BaseDetector: audit.NewBaseDetector("PATH_GPO_TO_DA", audit.CategoryAttackPaths),
	}
}

// Detect executes the detection
func (d *GpoToDADetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Find GPOs with weak ACLs (non-admin can modify)
	var vulnerableGpos []types.GPO

	for _, gpo := range data.GPOs {
		// Check if GPO has weak ACL (this would be populated by ACL analysis)
		if gpo.HasWeakACL {
			vulnerableGpos = append(vulnerableGpos, gpo)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "GPO Modification Path to Domain Admin",
		Description: "GPOs can be modified by non-admin users. If these GPOs apply to privileged users or DCs, attackers can achieve Domain Admin.",
		Count:       len(vulnerableGpos),
	}

	if data.IncludeDetails && len(vulnerableGpos) > 0 {
		var gpoNames []string
		entities := make([]types.AffectedEntity, len(vulnerableGpos))
		for i, gpo := range vulnerableGpos {
			name := gpo.DisplayName
			if name == "" {
				name = gpo.Name
			}
			gpoNames = append(gpoNames, name)
			entities[i] = types.AffectedEntity{
				Type:           "gpo",
				SAMAccountName: name,
			}
		}
		finding.AffectedEntities = entities
		finding.Details = map[string]interface{}{
			"vulnerableGpos": gpoNames,
			"attackVector":   "Modify GPO → Add malicious script/scheduled task → Execute on DA logon",
			"mitigation":     "Restrict GPO modification rights, implement GPO change monitoring",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGpoToDADetector())
}
