package governance

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// InvitationUnrestrictedDetector checks for unrestricted guest invitation policy
type InvitationUnrestrictedDetector struct {
	audit.BaseDetector
}

// NewInvitationUnrestrictedDetector creates a new detector
func NewInvitationUnrestrictedDetector() *InvitationUnrestrictedDetector {
	return &InvitationUnrestrictedDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_INVITATION_UNRESTRICTED", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *InvitationUnrestrictedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0

	// Check if guest invitation policy is unrestricted (empty or allows everyone)
	if data.AzureTenantConfig != nil {
		policy := data.AzureTenantConfig.GuestInvitationPolicy
		// If empty or not restricted, it's unrestricted
		if policy == "" || policy == "everyone" || policy == "all" {
			count = 1
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Guest Invitation Policy Unrestricted",
		Description: "Any user can invite external guests. Restrict to admins or specific roles.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInvitationUnrestrictedDetector())
}
