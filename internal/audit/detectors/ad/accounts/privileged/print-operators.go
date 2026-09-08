package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrintOperatorsDetector detects Print Operators membership
type PrintOperatorsDetector struct {
	audit.BaseDetector
}

// NewPrintOperatorsDetector creates a new detector
func NewPrintOperatorsDetector() *PrintOperatorsDetector {
	return &PrintOperatorsDetector{
		BaseDetector: audit.NewBaseDetector("PRINT_OPERATORS_MEMBER", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *PrintOperatorsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if len(u.MemberOf) == 0 {
			continue
		}
		for _, dn := range u.MemberOf {
			if strings.Contains(dn, "CN=Print Operators") {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Print Operators Member",
		Description: "Users in Print Operators group. Can load drivers and manage printers on DCs.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrintOperatorsDetector())
}
