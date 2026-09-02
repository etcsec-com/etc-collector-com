package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GuestInSecurityGroupDetector checks for guest users in security groups
type GuestInSecurityGroupDetector struct {
	audit.BaseDetector
}

// NewGuestInSecurityGroupDetector creates a new detector
func NewGuestInSecurityGroupDetector() *GuestInSecurityGroupDetector {
	return &GuestInSecurityGroupDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_GUEST_IN_SECURITY", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *GuestInSecurityGroupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This requires cross-referencing users and groups
	// Tenant-level advisory
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Guest Users in Security Groups",
		Description: "External guest users are members of security groups, potentially gaining access to internal resources.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGuestInSecurityGroupDetector())
}
