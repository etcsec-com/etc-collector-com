package privileged

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

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
	group := FindBuiltinGroup(data.Groups, "Server Operators")

	var members []ClassifiedMember
	if group != nil {
		members = ResolveRealMembers(data, group)
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
		Description: "Real members of the Server Operators group (users, nested groups, computers, foreign security principals). Can manage domain controllers. A broad foreign security principal (e.g. Authenticated Users, Everyone) means the privilege is effectively unrestricted.",
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
