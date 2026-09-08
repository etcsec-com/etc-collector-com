package governance

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NeverSignedInDetector checks for guest users who never signed in
type NeverSignedInDetector struct {
	audit.BaseDetector
}

// NewNeverSignedInDetector creates a new detector
func NewNeverSignedInDetector() *NeverSignedInDetector {
	return &NeverSignedInDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_NEVER_SIGNED_IN", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *NeverSignedInDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if isGuestUser(user) {
			hasSignedIn := (user.AzureLastSignInDateTime != nil && !user.AzureLastSignInDateTime.IsZero()) ||
				(user.AzureLastNonInteractiveSignInDateTime != nil && !user.AzureLastNonInteractiveSignInDateTime.IsZero())
			if !hasSignedIn {
				affected = append(affected, user)
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Guest Users Never Signed In",
		Description: "Invited guests who never accepted or signed in. Remove pending invitations.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNeverSignedInDetector())
}
