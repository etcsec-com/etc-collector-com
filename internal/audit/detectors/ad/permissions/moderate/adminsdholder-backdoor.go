package moderate

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminSDHolderBackdoorDetector detects unexpected ACL on AdminSDHolder object
type AdminSDHolderBackdoorDetector struct {
	audit.BaseDetector
}

// NewAdminSDHolderBackdoorDetector creates a new detector
func NewAdminSDHolderBackdoorDetector() *AdminSDHolderBackdoorDetector {
	return &AdminSDHolderBackdoorDetector{
		BaseDetector: audit.NewBaseDetector("ADMINSDHOLDER_BACKDOOR", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *AdminSDHolderBackdoorDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if strings.Contains(ace.ObjectDN, "CN=AdminSDHolder,CN=System") {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "AdminSDHolder Backdoor",
		Description: "Unexpected ACL on AdminSDHolder object. Persistent permissions on admin accounts.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(affected, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminSDHolderBackdoorDetector())
}
