package membership

import (
	"context"
	"strconv"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GpoModifyRightsDetector checks for Group Policy Creator Owners membership
type GpoModifyRightsDetector struct {
	audit.BaseDetector
}

// NewGpoModifyRightsDetector creates a new detector
func NewGpoModifyRightsDetector() *GpoModifyRightsDetector {
	return &GpoModifyRightsDetector{
		BaseDetector: audit.NewBaseDetector("GPO_MODIFY_RIGHTS", audit.CategoryGroups),
	}
}

// gpoCreatorOwnersSIDSuffixes matches Group Policy Creator Owners by its
// fixed, domain-relative RID -520 (Microsoft Learn, "Security identifiers",
// learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers),
// not by its English CN: the previous strings.Contains(groupDN,
// "CN=Group Policy Creator Owners") match was blind on a localized forest
// (the CN differs per language) and false-positived on any homonym group
// whose CN merely starts with the same English text. Nested/transitive
// group membership is not followed here (same scope limit as
// privgroups.IsMemberOfAny).
var gpoCreatorOwnersSIDSuffixes = []string{"-520"}

// primaryGroupIsGpoCreatorOwners reports whether u's PRIMARY group - not
// memberOf; AD never writes a memberOf backlink for a user's primary group,
// so it must be checked separately - is Group Policy Creator Owners.
// u.PrimaryGroupID is a bare RID, turned into a full SID by prefixing
// data.DomainInfo.DomainSID and looked up by EXACT match (not suffix) in
// data.ObjectBySID, then confirmed against gpoDNs (the -520 set built by
// privgroups.DNsBySIDSuffix).
//
// When data.DomainInfo or its DomainSID is empty (not collected), no
// membership is granted here: this fails CLOSED, never open, rather than
// trusting an unverifiable RID.
func primaryGroupIsGpoCreatorOwners(data *audit.DetectorData, u types.User, gpoDNs map[string]bool) bool {
	if data.DomainInfo == nil || data.DomainInfo.DomainSID == "" {
		return false
	}
	primaryGroupSID := data.DomainInfo.DomainSID + "-" + strconv.Itoa(u.PrimaryGroupID)
	meta := data.ObjectBySID[primaryGroupSID]
	if meta == nil {
		return false
	}
	return gpoDNs[strings.ToLower(meta.DN)]
}

// Detect executes the detection
func (d *GpoModifyRightsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	gpoDNs := privgroups.DNsBySIDSuffix(data, gpoCreatorOwnersSIDSuffixes)

	for _, user := range data.Users {
		if privgroups.IsMemberOfAny(user.MemberOf, gpoDNs) || primaryGroupIsGpoCreatorOwners(data, user, gpoDNs) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Group Policy Creator Owners Member",
		Description: "Users in Group Policy Creator Owners group. Can create/modify GPOs and execute code on domain machines.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGpoModifyRightsDetector())
}
