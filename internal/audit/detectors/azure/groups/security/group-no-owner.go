package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoOwnerDetector checks for groups without owners
type NoOwnerDetector struct {
	audit.BaseDetector
}

// NewNoOwnerDetector creates a new detector
func NewNoOwnerDetector() *NoOwnerDetector {
	return &NoOwnerDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_NO_OWNER", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *NoOwnerDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory (we don't have owner data in current Group struct)
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Groups Without Owners",
		Description: "Groups without designated owners cannot be properly governed.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoOwnerDetector())
}
