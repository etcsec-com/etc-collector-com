package membership

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
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

// Detect executes the detection
func (d *GpoModifyRightsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		for _, groupDN := range user.MemberOf {
			if strings.Contains(groupDN, "CN=Group Policy Creator Owners") {
				affected = append(affected, user)
				break
			}
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
