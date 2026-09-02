package delegation

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// InAdminGroupDetector checks for computers in admin groups
type InAdminGroupDetector struct {
	audit.BaseDetector
}

// NewInAdminGroupDetector creates a new detector
func NewInAdminGroupDetector() *InAdminGroupDetector {
	return &InAdminGroupDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_IN_ADMIN_GROUP", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *InAdminGroupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer
	adminGroups := []string{"Domain Admins", "Enterprise Admins"}

	for _, c := range data.Computers {
		for _, memberOf := range c.MemberOf {
			for _, adminGroup := range adminGroups {
				if strings.Contains(memberOf, "CN="+adminGroup) {
					affected = append(affected, c)
					break
				}
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Computer in Admin Group",
		Description: "Computer account in Domain Admins or Enterprise Admins. Computer compromise leads to domain admin access.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInAdminGroupDetector())
}
