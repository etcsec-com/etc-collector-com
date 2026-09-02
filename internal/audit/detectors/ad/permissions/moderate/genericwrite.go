package moderate

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GenericWriteDetector detects GenericWrite permission on sensitive objects
type GenericWriteDetector struct {
	audit.BaseDetector
}

// NewGenericWriteDetector creates a new detector
func NewGenericWriteDetector() *GenericWriteDetector {
	return &GenericWriteDetector{
		BaseDetector: audit.NewBaseDetector("ACL_GENERICWRITE", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *GenericWriteDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const genericWrite = 0x40000000

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if (ace.AccessMask & genericWrite) != 0 {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ACL GenericWrite",
		Description: "GenericWrite permission on sensitive AD objects. Can modify many object attributes.",
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
	audit.MustRegister(NewGenericWriteDetector())
}
