package kerberos

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminAsrepRoastableDetector checks for enabled privileged accounts without
// Kerberos pre-authentication. Scoped to active accounts: the KDC rejects the
// AS-REQ on account status before pre-authentication is ever considered, so a
// disabled account carrying this bit is not exploitable today - see
// AdminAsrepRoastableOnDisabledAccountDetector for the disabled-account claim,
// reported separately at Low. Same split as the neighboring
// AsrepRoastingRiskDetector / AsrepRoastingOnDisabledAccountDetector on the
// same UAC bit.
type AdminAsrepRoastableDetector struct {
	audit.BaseDetector
}

// NewAdminAsrepRoastableDetector creates a new detector
func NewAdminAsrepRoastableDetector() *AdminAsrepRoastableDetector {
	return &AdminAsrepRoastableDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_ASREP_ROASTABLE", audit.CategoryKerberos),
	}
}

// privilegedGroupDNsBySIDAsrep returns the lowercased DN of every collected
// group whose SID ends in one of the RID suffixes in
// types.PrivilegedSIDSuffixes - the same non-localized, SID-based match
// SensitiveDelegationDetector uses (accounts/privileged package), applied
// here to the same collector output. Shared by both halves of this
// split (AdminAsrepRoastableDetector and
// AdminAsrepRoastableOnDisabledAccountDetector) so they classify "privileged"
// identically. Not reused across packages: `privileged.privilegedGroupDNsBySID`
// is unexported, so this is the kerberos package's own copy of the same
// mechanism against the same shared table - not a duplicated definition of
// "privileged".
//
// The lookup runs entirely through DetectorData.ObjectBySID: engine.collectData
// builds it in two steps (engine.go) - buildObjectIndex indexes every
// types.Group by g.ObjectSID (detector.go's DetectorData.ObjectByDN cache),
// then buildSIDIndex reverses that DN-keyed cache into the SID-keyed view
// documented at DetectorData.ObjectBySID (detector.go). g.ObjectSID itself
// comes straight off the wire: providers/ldap/parser.go's parseGroup decodes
// the group's raw "objectSid" LDAP attribute.
//
// A privileged group whose SID never makes it into that index - not
// collected into data.Groups, or collected with an empty ObjectSID - is
// silently excluded here: none of its members can be identified as
// privileged by this detector. That is a property of the shared index, not
// of this file, and it fails closed (under-detection), never open.
func privilegedGroupDNsBySIDAsrep(data *audit.DetectorData) map[string]bool {
	dns := make(map[string]bool, len(types.PrivilegedSIDSuffixes))
	for sid, meta := range data.ObjectBySID {
		if meta == nil || meta.EntityType != types.EntityTypeGroup {
			continue
		}
		for suffix := range types.PrivilegedSIDSuffixes {
			if strings.HasSuffix(sid, suffix) {
				dns[strings.ToLower(meta.DN)] = true
				break
			}
		}
	}
	return dns
}

// isMemberOfPrivilegedGroupAsrep reports whether any of a user's MemberOf DNs
// resolves to a privileged group per privilegedGroupDNsBySIDAsrep.
func isMemberOfPrivilegedGroupAsrep(memberOf []string, privilegedDNs map[string]bool) bool {
	for _, dn := range memberOf {
		if privilegedDNs[strings.ToLower(dn)] {
			return true
		}
	}
	return false
}

// Detect executes the detection
func (d *AdminAsrepRoastableDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	privilegedDNs := privilegedGroupDNsBySIDAsrep(data)

	for _, user := range data.Users {
		if user.Disabled {
			continue
		}

		if (user.UserAccountControl & types.UACDontRequirePreauth) == 0 {
			continue
		}

		if isMemberOfPrivilegedGroupAsrep(user.MemberOf, privilegedDNs) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Privileged Account AS-REP Roastable",
		Description: "Enabled privileged accounts (Domain Admins, Domain Controllers, Schema Admins, Enterprise Admins, Key Admins, Enterprise Key Admins, Administrators, Account Operators, Server Operators, Print Operators, Backup Operators) without Kerberos pre-authentication. High-value targets for AS-REP roasting attacks - immediate domain compromise risk.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		}
		finding.Details = map[string]interface{}{
			"risk":           "CRITICAL - Privileged account password hash can be obtained offline",
			"recommendation": "Enable Kerberos pre-authentication immediately for all privileged accounts",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminAsrepRoastableDetector())
}
