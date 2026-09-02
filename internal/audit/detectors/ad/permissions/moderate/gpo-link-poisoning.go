package moderate

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GPOLinkPoisoningDetector detects weak ACLs on Group Policy Objects
type GPOLinkPoisoningDetector struct {
	audit.BaseDetector
}

// NewGPOLinkPoisoningDetector creates a new detector
func NewGPOLinkPoisoningDetector() *GPOLinkPoisoningDetector {
	return &GPOLinkPoisoningDetector{
		BaseDetector: audit.NewBaseDetector("GPO_LINK_POISONING", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *GPOLinkPoisoningDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const genericWrite = 0x40000000
	const genericAll = 0x10000000
	const writeDACL = 0x00040000

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		isGPO := strings.Contains(ace.ObjectDN, "CN=Policies,CN=System")
		hasDangerousPermission := (ace.AccessMask&genericAll) != 0 ||
			(ace.AccessMask&genericWrite) != 0 ||
			(ace.AccessMask&writeDACL) != 0

		if isGPO && hasDangerousPermission {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "GPO Link Poisoning",
		Description: "Weak ACLs on Group Policy Objects. Can modify GPO to execute code on targeted systems.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		entities := make([]types.AffectedEntity, len(uniqueObjects))
		for i, dn := range uniqueObjects {
			entities[i] = types.AffectedEntity{
				Type: "gpo",
				DN:   dn,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGPOLinkPoisoningDetector())
}
