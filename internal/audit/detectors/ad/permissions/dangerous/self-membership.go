package dangerous

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SelfMembershipDetector detects self-membership rights on groups
type SelfMembershipDetector struct {
	audit.BaseDetector
}

// NewSelfMembershipDetector creates a new detector
func NewSelfMembershipDetector() *SelfMembershipDetector {
	return &SelfMembershipDetector{
		BaseDetector: audit.NewBaseDetector("ACL_SELF_MEMBERSHIP", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *SelfMembershipDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Self-membership GUID: bf9679c0-0de6-11d0-a285-00aa003049e2
	const selfMembershipGUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	const writeSelf = 0x8 // ADS_RIGHT_DS_SELF

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		// A DENY ace grants nothing (DET_10).
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}

		// "Self-membership" is only meaningful on a GROUP: you add yourself to
		// a group, not to a user or an OU. Without this the detector claimed
		// self-membership rights over 546 users, 352 OUs and the domain root
		// (T_024).
		if meta := data.ObjectByDN[ace.ObjectDN]; meta == nil || meta.EntityType != types.EntityTypeGroup {
			continue
		}

		// Built-in admins can obviously add members to any group.
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}

		// The right must actually be self-membership: either the ACE names the
		// Self-Membership extended right, or it is an unscoped validated write
		// (ObjectType empty) carrying DS_SELF.
		//
		// The removed `strings.Contains(ObjectType, "member")` was a substring
		// test against a GUID — it matched any GUID whose hex digits happened to
		// spell those characters, and never expressed self-membership at all.
		//
		// Full control is deliberately NOT accepted here: it is already reported
		// by ACL_GENERICALL, and folding it in is what made these detectors emit
		// byte-identical entity sets.
		guid := strings.ToLower(ace.ObjectType)
		isSelfMembership := guid == selfMembershipGUID ||
			(guid == "" && (ace.AccessMask&writeSelf) != 0)

		if isSelfMembership {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Self-Membership Rights",
		Description: "Principals with self-membership rights on groups. Allows adding oneself to a group, potentially gaining elevated privileges.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(affected, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSelfMembershipDetector())
}
