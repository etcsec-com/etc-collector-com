package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminLogonCountLowDetector detects admin accounts with low logon count
type AdminLogonCountLowDetector struct {
	audit.BaseDetector
}

// NewAdminLogonCountLowDetector creates a new detector
func NewAdminLogonCountLowDetector() *AdminLogonCountLowDetector {
	return &AdminLogonCountLowDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_LOGON_COUNT_LOW", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *AdminLogonCountLowDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Must be enabled
		if u.Disabled {
			continue
		}
		// Must be marked as admin (adminCount = true)
		if !u.AdminCount {
			continue
		}
		// Low logon count (less than 5)
		if u.LogonCount < 5 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Admin Account with Low Logon Count",
		Description: "Administrative accounts (adminCount=1) with fewer than 5 logons. May indicate unused privileged accounts that should be reviewed or disabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminLogonCountLowDetector())
}
