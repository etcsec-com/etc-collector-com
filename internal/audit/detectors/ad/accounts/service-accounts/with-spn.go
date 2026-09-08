package serviceaccounts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WithSpnDetector detects service accounts with SPN
type WithSpnDetector struct {
	audit.BaseDetector
}

// NewWithSpnDetector creates a new detector
func NewWithSpnDetector() *WithSpnDetector {
	return &WithSpnDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_WITH_SPN", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *WithSpnDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User
	spnCount := 0

	for _, u := range data.Users {
		// Must have SPN
		if len(u.ServicePrincipalNames) == 0 {
			continue
		}
		// Must be enabled
		if u.Disabled {
			continue
		}

		affected = append(affected, u)
		spnCount += len(u.ServicePrincipalNames)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Service Account with SPN (Kerberoasting Target)",
		Description: "User accounts with Service Principal Name configured. These accounts are targets for Kerberoasting attacks where attackers request TGS tickets and crack them offline.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Use gMSA (Group Managed Service Accounts) instead. For existing accounts, ensure strong passwords (25+ chars) and regular rotation.",
			"spnCount":       spnCount,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWithSpnDetector())
}
