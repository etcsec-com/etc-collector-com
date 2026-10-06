package security

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OwnerIsGuestDetector checks for groups owned by guest users
type OwnerIsGuestDetector struct {
	audit.BaseDetector
}

// NewOwnerIsGuestDetector creates a new detector
func NewOwnerIsGuestDetector() *OwnerIsGuestDetector {
	return &OwnerIsGuestDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_OWNER_IS_GUEST", audit.CategoryGroups),
	}
}

// ownerUserTypeIndex maps a UserPrincipalName (folded to lower case) to that
// user's AzureUserType, as actually collected on data.Users. Group.AzureOwners
// only carries owner identifiers (see enrichGroupsWithOwners in
// internal/providers/azure/client.go - userType isn't fetched there because
// group owners are a polymorphic collection and userType only exists on
// user objects). Cross-referencing against data.Users is how this detector
// learns which owners are guests without guessing from the UPN string.
func ownerUserTypeIndex(users []types.User) map[string]string {
	index := make(map[string]string, len(users))
	for _, u := range users {
		if u.UserPrincipalName == "" || u.AzureUserType == nil {
			continue
		}
		index[strings.ToLower(u.UserPrincipalName)] = *u.AzureUserType
	}
	return index
}

// Detect executes the detection
//
// Only groups with AzureOwnersProbed==true are considered - a group never
// probed for owners can say nothing about who owns it. For each of its
// owners, the real Graph-reported userType is looked up via
// ownerUserTypeIndex; an owner whose userType could not be resolved this way
// (not present in data.Users - e.g. a service principal owner, or the user
// collection didn't reach it) is treated as unknown and never counted as a
// guest. The UPN's domain is never used as a substitute signal.
func (d *OwnerIsGuestDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	userTypes := ownerUserTypeIndex(data.Users)

	var affected []types.Group
	for _, group := range data.Groups {
		if !group.AzureOwnersProbed {
			continue
		}
		for _, owner := range group.AzureOwners {
			if userTypes[strings.ToLower(owner)] == "Guest" {
				affected = append(affected, group)
				break
			}
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "Groups Owned by Guest Users",
		Description: "At least one owner of this group is an external guest account (userType " +
			"'Guest', cross-referenced against collected user data), meaning the group can be " +
			"managed from outside the organization. Owners whose userType could not be resolved " +
			"are not counted either way, rather than guessed from their UPN.",
		Count: len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewOwnerIsGuestDetector())
}
