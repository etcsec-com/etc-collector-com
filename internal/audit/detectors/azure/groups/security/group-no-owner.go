package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoOwnerDetector checks for groups without owners
type NoOwnerDetector struct {
	audit.BaseDetector
}

// NewNoOwnerDetector creates a new detector
func NewNoOwnerDetector() *NoOwnerDetector {
	return &NoOwnerDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_NO_OWNER", audit.CategoryGroups),
	}
}

// Detect executes the detection
//
// Reads AzureOwners / AzureOwnersProbed, populated by the provider's
// enrichGroupsWithOwners (internal/providers/azure/client.go) via GET
// /groups/{id}/owners. AzureOwnersProbed distinguishes "the question was
// never asked" (transport error, decode error, or the collection budget
// expired before reaching this group) from "asked, and the answer was
// zero" - only the latter counts. A group with AzureOwnersProbed==false is
// NEVER counted here, regardless of what AzureOwners happens to hold.
//
// Groups synced from on-premises AD (AzureOnPremisesSyncEnabled==true) are
// excluded: their governance lives in the source directory, not in Entra -
// they structurally have no Entra owner, and counting them would recreate
// the mass false positive this detector was retired for.
func (d *NoOwnerDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Group

	for _, group := range data.Groups {
		if !group.AzureOwnersProbed {
			continue
		}
		if group.AzureOnPremisesSyncEnabled != nil && *group.AzureOnPremisesSyncEnabled {
			continue
		}
		if len(group.AzureOwners) == 0 {
			affected = append(affected, group)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "Groups Without Owners",
		Description: "Groups without a designated owner cannot be properly governed: no one is " +
			"accountable for reviewing membership or deciding whether the group is still needed. " +
			"Groups synced from on-premises Active Directory are excluded - their governance lives " +
			"in the source directory, not Entra.",
		Count: len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoOwnerDetector())
}
