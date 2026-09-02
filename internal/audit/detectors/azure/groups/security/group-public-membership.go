package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PublicMembershipDetector checks for groups with public membership
type PublicMembershipDetector struct {
	audit.BaseDetector
}

// NewPublicMembershipDetector creates a new detector
func NewPublicMembershipDetector() *PublicMembershipDetector {
	return &PublicMembershipDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_PUBLIC_MEMBERSHIP", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *PublicMembershipDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Groups with Public Membership",
		Description: "Groups allowing any user to join without approval increase risk of unauthorized access.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPublicMembershipDetector())
}
