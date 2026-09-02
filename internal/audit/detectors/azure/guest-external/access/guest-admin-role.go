package access

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminRoleDetector checks for guest users with administrative roles
type AdminRoleDetector struct {
	audit.BaseDetector
}

// NewAdminRoleDetector creates a new detector
func NewAdminRoleDetector() *AdminRoleDetector {
	return &AdminRoleDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_ADMIN_ROLE", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *AdminRoleDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Advisory: cross-referencing role assignments with guest users would require
	// additional data. Tenant-level advisory.
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Guest User with Administrative Role",
		Description: "External guest users have administrative directory roles. This is a critical security risk.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminRoleDetector())
}
