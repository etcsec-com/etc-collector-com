package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SensitiveDelegationDetector detects enabled privileged accounts with
// unconstrained delegation. Scoped to active accounts: a disabled account can
// obtain neither its own ticket-granting ticket ([MS-KILE] "Check Account
// Policy for Every TGT Request" - KDC_ERR_CLIENT_REVOKED), which closes the
// delegation-origin role, nor - measured directly against a live KDC - a
// service ticket toward its own SPN, which closes the delegation-target role
// too - see SensitiveDelegationOnDisabledAccountDetector, which reports that
// disabled population separately, at Low.
type SensitiveDelegationDetector struct {
	audit.BaseDetector
}

// NewSensitiveDelegationDetector creates a new detector
func NewSensitiveDelegationDetector() *SensitiveDelegationDetector {
	return &SensitiveDelegationDetector{
		BaseDetector: audit.NewBaseDetector("SENSITIVE_DELEGATION", audit.CategoryAccounts),
	}
}

// privilegedGroupDNsBySID returns the lowercased DN of every collected group
// whose SID ends in one of the RID suffixes in types.PrivilegedSIDSuffixes -
// the same non-localized, SID-based match audit.IsBuiltinAdminTrustee already
// applies to ACL trustees, applied here to group membership instead. Shared
// by both halves of this split (SensitiveDelegationDetector and
// SensitiveDelegationOnDisabledAccountDetector) so they classify "privileged"
// identically.
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
func privilegedGroupDNsBySID(data *audit.DetectorData) map[string]bool {
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

// isMemberOfPrivilegedGroup reports whether any of a user's MemberOf DNs
// resolves to a privileged group per privilegedGroupDNsBySID.
func isMemberOfPrivilegedGroup(memberOf []string, privilegedDNs map[string]bool) bool {
	for _, dn := range memberOf {
		if privilegedDNs[strings.ToLower(dn)] {
			return true
		}
	}
	return false
}

// Detect executes the detection
func (d *SensitiveDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	privilegedDNs := privilegedGroupDNsBySID(data)

	for _, u := range data.Users {
		if u.Disabled {
			continue
		}

		if len(u.MemberOf) == 0 {
			continue
		}

		hasUnconstrainedDeleg := (u.UserAccountControl & types.UACTrustedForDelegation) != 0

		if !hasUnconstrainedDeleg {
			continue
		}

		if isMemberOfPrivilegedGroup(u.MemberOf, privilegedDNs) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Sensitive Account with Delegation",
		Description: "Enabled privileged accounts (Domain Admins, Domain Controllers, Schema Admins, Enterprise Admins, Key Admins, Enterprise Key Admins, Administrators, Account Operators, Server Operators, Print Operators, Backup Operators) with unconstrained delegation. Extreme security risk.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSensitiveDelegationDetector())
}
