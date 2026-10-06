package access

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoCAPolicyDetector checks if any CA policy targets guest users
type NoCAPolicyDetector struct {
	audit.BaseDetector
}

// NewNoCAPolicyDetector creates a new detector
func NewNoCAPolicyDetector() *NoCAPolicyDetector {
	return &NoCAPolicyDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_NO_CA_POLICY", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
//
// Known limitation (non vu, not fixable in this detector alone): this only
// recognizes guest/external targeting expressed as a string inside
// IncludeUsers (the legacy sentinel value "GuestsOrExternalUsers", or any
// name/ID substring-matching "guest"/"external"). Microsoft Graph's newer,
// more granular conditions.users.includeGuestsOrExternalUsers object (guest
// types: b2bCollaborationGuest, b2bCollaborationMember, b2bDirectConnectUser,
// otherExternalUser, serviceProvider - Microsoft Learn, "Authentication and
// Conditional Access for B2B users", learn.microsoft.com/en-us/entra/
// external-id/authentication-conditional-access, "Include > All guest and
// external users") is a separate field entirely and is never captured by
// internal/providers/azure/client.go's convertConditionalAccessPolicy for
// this flat type (it exists only on the separate
// ConditionalAccessPolicyDetail type in pkg/types/cadetail.go, used for a
// different purpose). A tenant scoping guests exclusively through that
// modern mechanism is invisible to this check. Fixing this needs a new field
// on types.ConditionalAccessPolicy and a collector change, both out of this
// detector's scope.
func (d *NoCAPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasPolicyForGuests := false

	// Check if any enabled CA policy targets guests
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}

		// Check if policy targets guests
		for _, user := range policy.IncludeUsers {
			if strings.Contains(strings.ToLower(user), "guest") ||
				strings.Contains(strings.ToLower(user), "external") {
				hasPolicyForGuests = true
				break
			}
		}

		if hasPolicyForGuests {
			break
		}
	}

	count := 0
	if !hasPolicyForGuests {
		count = 1
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "No CA Policy for Guest Users",
		Description: "No CA policy specifically targets guest or external users by name/ID matching. " +
			"Targeting done exclusively via Microsoft's newer 'All guest and external users' condition " +
			"is not currently detected (collector does not capture includeGuestsOrExternalUsers).",
		Count: count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoCAPolicyDetector())
}
