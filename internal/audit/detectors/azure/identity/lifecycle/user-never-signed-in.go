package lifecycle

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDNeverSignedIn       = "USER_NEVER_SIGNED_IN"
	CategoryNeverSignedIn = audit.CategoryIdentity
)

// NeverSignedInDetector checks for users that have never signed in
type NeverSignedInDetector struct {
	audit.BaseDetector
}

// NewUserNeverSignedInDetector creates a new never signed in detector
func NewUserNeverSignedInDetector() *NeverSignedInDetector {
	return &NeverSignedInDetector{
		BaseDetector: audit.NewBaseDetector(IDNeverSignedIn, CategoryNeverSignedIn),
	}
}

// Detect finds user accounts that have never signed in
func (d *NeverSignedInDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDNeverSignedIn,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryNeverSignedIn),
		Title:       "Users Never Signed In",
		Description: "User accounts that have never signed in. These may be provisioning errors or abandoned accounts.",
		Count:       0,
	}

	var affected []types.User

	for _, user := range data.Users {
		if user.Disabled {
			continue
		}

		hasSignedIn := (user.AzureLastSignInDateTime != nil && !user.AzureLastSignInDateTime.IsZero()) ||
			(user.AzureLastNonInteractiveSignInDateTime != nil && !user.AzureLastNonInteractiveSignInDateTime.IsZero())
		if !hasSignedIn {
			affected = append(affected, user)
		}
	}

	finding.Count = len(affected)

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUserNeverSignedInDetector())
}
