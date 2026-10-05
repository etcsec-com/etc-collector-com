package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NeverLoggedOnDetector detects accounts that have never logged on
type NeverLoggedOnDetector struct {
	audit.BaseDetector
}

// NewNeverLoggedOnDetector creates a new detector
func NewNeverLoggedOnDetector() *NeverLoggedOnDetector {
	return &NeverLoggedOnDetector{
		BaseDetector: audit.NewBaseDetector("NEVER_LOGGED_ON", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *NeverLoggedOnDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Must be enabled
		if u.Disabled {
			continue
		}
		// AD logon timestamps
		hasADLogon := !u.LastLogon.IsZero() || !u.LastLogonTimestamp.IsZero()
		// Azure sign-in timestamps
		hasAzureLogon := (u.AzureLastSignInDateTime != nil && !u.AzureLastSignInDateTime.IsZero()) ||
			(u.AzureLastNonInteractiveSignInDateTime != nil && !u.AzureLastNonInteractiveSignInDateTime.IsZero())
		if !hasADLogon && !hasAzureLogon {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Never Logged On",
		Description: "Enabled user accounts that have never logged into the domain. May indicate orphaned accounts, provisioning issues, or unused accounts that should be disabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNeverLoggedOnDetector())
}
