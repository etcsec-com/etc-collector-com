package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ACLAbuseDetector checks for computers with dangerous ACL permissions
type ACLAbuseDetector struct {
	audit.BaseDetector
}

// NewACLAbuseDetector creates a new detector
func NewACLAbuseDetector() *ACLAbuseDetector {
	return &ACLAbuseDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_ACL_ABUSE", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *ACLAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.DangerousACL {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Computer ACL Abuse",
		Description: "Computer with dangerous ACL permissions. Can modify computer object properties and escalate privileges.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewACLAbuseDetector())
}
