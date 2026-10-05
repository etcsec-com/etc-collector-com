package privileged

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// serverOperatorsSID is the well-known SID for the built-in Server
// Operators group (S-1-5-32-549), identical in every forest regardless of
// localization (e.g. "Opérateurs de serveur" in fr-FR) or of a same-named
// decoy group placed elsewhere in the directory - see FindGroupBySID.
const serverOperatorsSID = "S-1-5-32-549"

// ServerOperatorsDetector detects Server Operators membership
type ServerOperatorsDetector struct {
	audit.BaseDetector
}

// NewServerOperatorsDetector creates a new detector
func NewServerOperatorsDetector() *ServerOperatorsDetector {
	return &ServerOperatorsDetector{
		BaseDetector: audit.NewBaseDetector("SERVER_OPERATORS_MEMBER", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *ServerOperatorsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// reads the group's own real membership (Members/Member LDAP
	// attribute) instead of scanning data.Users[].MemberOf, which only ever
	// shows direct user members and stayed silent when Server Operators'
	// only member was a foreignSecurityPrincipal (e.g. S-1-5-11 Authenticated
	// Users, seen on the lab DC).
	group := FindGroupBySID(data, serverOperatorsSID)

	var members []ClassifiedMember
	if group != nil {
		for _, m := range ResolveRealMembers(data, group) {
			// A disabled user or computer cannot authenticate ([MS-KILE]
			// "Check Account Policy for Every TGT Request" -
			// KDC_ERR_CLIENT_REVOKED), so it cannot exercise the privilege
			// while disabled - reported separately, at Low, by
			// ServerOperatorsOnDisabledAccountDetector. Nested groups, FSPs
			// and unknown members have no such state and stay here.
			if (m.Kind == MemberKindUser || m.Kind == MemberKindComputer) && m.Disabled {
				continue
			}
			members = append(members, m)
		}
	}

	entities := make([]types.AffectedEntity, len(members))
	for i, m := range members {
		entities[i] = m.Entity
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Server Operators Member",
		Description: "Active (non-disabled) real members of the Server Operators group: users, nested groups, computers, and foreign security principals. Members can sign in interactively to domain controllers, create and delete shared resources, stop and start services, back up and restore files, format the hard disk, and shut down the domain controller. A broad foreign security principal (e.g. Authenticated Users, Everyone) means the privilege is effectively unrestricted. Disabled user and computer members are reported separately by SERVER_OPERATORS_MEMBER_ON_DISABLED_ACCOUNT.",
		Count:       len(members),
	}

	if data.IncludeDetails && len(entities) > 0 {
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewServerOperatorsDetector())
}
