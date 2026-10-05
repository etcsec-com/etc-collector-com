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

	// Graph's authorizationPolicy.allowInvitesFrom has exactly 4 values:
	// "none", "adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers",
	// "everyone" (msgraph-sdk-go models.AllowInvitesFrom.String()). Only
	// "everyone" actually lets a guest invite another guest - the other two
	// non-"none" values restrict inviting to admins/members, NOT guests,
	// despite containing the substring "guest" in their name. Empty policy
	// means the read failed/never happened: no verdict, never guess.
	if data.AzureTenantConfig != nil && strings.EqualFold(data.AzureTenantConfig.GuestInvitationPolicy, "everyone") {
		count = 1
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
