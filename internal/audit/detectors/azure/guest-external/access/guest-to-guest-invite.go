package access

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GuestToGuestInviteDetector checks if guests can invite other guests
type GuestToGuestInviteDetector struct {
	audit.BaseDetector
}

// NewGuestToGuestInviteDetector creates a new detector
func NewGuestToGuestInviteDetector() *GuestToGuestInviteDetector {
	return &GuestToGuestInviteDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_TO_GUEST_INVITE", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *GuestToGuestInviteDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0

	// Check if guest invitation policy allows guests to invite
	if data.AzureTenantConfig != nil {
		policy := data.AzureTenantConfig.GuestInvitationPolicy
		// If policy allows guests or is unrestricted
		if policy == "" || strings.Contains(strings.ToLower(policy), "guest") {
			count = 1
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Guests Can Invite Other Guests",
		Description: "Guest users can invite other external users, creating an uncontrolled invitation chain.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGuestToGuestInviteDetector())
}
