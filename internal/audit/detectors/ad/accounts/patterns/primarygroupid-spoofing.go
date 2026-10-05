package patterns

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrimaryGroupIdSpoofingDetector detects primaryGroupID spoofing
type PrimaryGroupIdSpoofingDetector struct {
	audit.BaseDetector
}

// NewPrimaryGroupIdSpoofingDetector creates a new detector
func NewPrimaryGroupIdSpoofingDetector() *PrimaryGroupIdSpoofingDetector {
	return &PrimaryGroupIdSpoofingDetector{
		BaseDetector: audit.NewBaseDetector("PRIMARYGROUPID_SPOOFING", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *PrimaryGroupIdSpoofingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	// Standard primaryGroupID for Domain Users is 513
	const standardPrimaryGroupID = 513

	for _, u := range data.Users {
		if u.PrimaryGroupID == 0 || u.PrimaryGroupID == standardPrimaryGroupID {
			continue
		}
		if isKnownLegitimateNonStandardPrimaryGroup(u) {
			continue
		}
		affected = append(affected, u)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "primaryGroupID Spoofing",
		Description: "User accounts with a non-standard primaryGroupID, excluding Windows' own factory-default exceptions (e.g. the built-in Guest account, gMSAs). Can be used to hide group membership from tools/admins that only enumerate explicit group membership (memberOf) and never check primaryGroupID.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

// isKnownLegitimateNonStandardPrimaryGroup excludes the two cases where
// Windows itself assigns a non-513 primaryGroupID by factory default among
// objects reachable through data.Users. GetUsers's LDAP filter
// (internal/providers/ldap/client.go, userFilter) is
// "(&(objectClass=user)(|(objectCategory=person)(objectClass=msDS-
// GroupManagedServiceAccount)))" - computer objects never match it, so
// Domain Controllers (RID 516) and RODCs (RID 521), which get their
// non-513 primaryGroupID from being computer objects, can never appear in
// data.Users at all. Only two default exceptions are actually reachable:
//
//   - The built-in Guest account (well-known RID 501). Microsoft Learn,
//     "Security Identifiers" documents S-1-5-<domain>-514 (Domain Guests)
//     as "a global group that, by default, has only one member: the
//     domain's built-in Guest account"
//     (learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/
//     understand-security-identifiers) - Guest's primary group is that
//     group, RID 514, not 513.
//   - gMSA accounts. [MS-ADSC] defines msDS-GroupManagedServiceAccount as
//     subClassOf computer (learn.microsoft.com/en-us/openspecs/
//     windows_protocols/ms-adsc/219549d4-39eb-4771-bb8c-b3593ff6be48), so a
//     newly-created gMSA gets the same default primary group as any other
//     computer object: RID 515 (Domain Computers) - per the same "Security
//     Identifiers" RID table cited above.
//
// krbtgt was considered (the ecart this fix closes named it as a candidate
// exception) and rejected: Microsoft's own guidance and community
// documentation on krbtgt describe it as remaining a member of only
// "Domain Users" and "Denied RODC Password Replication Group", consistent
// with the ordinary default primaryGroupID of 513 - no source documents a
// special non-513 default for krbtgt. A non-513 krbtgt is exactly the kind
// of anomaly this detector exists to catch, not a case to exclude.
func isKnownLegitimateNonStandardPrimaryGroup(u types.User) bool {
	const (
		guestRIDSuffix                = "-501"
		domainGuestsPrimaryGroupID    = 514
		domainComputersPrimaryGroupID = 515
	)

	if u.PrimaryGroupID == domainGuestsPrimaryGroupID && strings.HasSuffix(u.ObjectSID, guestRIDSuffix) {
		return true
	}
	if u.PrimaryGroupID == domainComputersPrimaryGroupID && u.IsGMSA {
		return true
	}
	return false
}

func init() {
	audit.MustRegister(NewPrimaryGroupIdSpoofingDetector())
}
