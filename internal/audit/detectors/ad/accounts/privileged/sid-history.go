package privileged

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SidHistoryDetector detects SID history attribute
type SidHistoryDetector struct {
	audit.BaseDetector
}

// NewSidHistoryDetector creates a new detector
func NewSidHistoryDetector() *SidHistoryDetector {
	return &SidHistoryDetector{
		BaseDetector: audit.NewBaseDetector("SID_HISTORY", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *SidHistoryDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if len(u.SIDHistory) > 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "SID History Present",
		Description: "User accounts with sIDHistory attribute. Can be abused for privilege escalation.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSidHistoryDetector())
}
