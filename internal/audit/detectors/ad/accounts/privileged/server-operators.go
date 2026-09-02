package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
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
	var affected []types.User

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}
		for _, dn := range u.MemberOf {
			if strings.Contains(dn, "CN=Server Operators") {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Server Operators Member",
		Description: "Users in Server Operators group. Can manage domain controllers.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewServerOperatorsDetector())
}
