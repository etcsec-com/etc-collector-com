package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OwnerIsGuestDetector checks for groups owned by guest users
type OwnerIsGuestDetector struct {
	audit.BaseDetector
}

// NewOwnerIsGuestDetector creates a new detector
func NewOwnerIsGuestDetector() *OwnerIsGuestDetector {
	return &OwnerIsGuestDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_OWNER_IS_GUEST", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *OwnerIsGuestDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Groups Owned by Guest Users",
		Description: "Groups owned by external guest users may be managed outside organizational control.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewOwnerIsGuestDetector())
}
