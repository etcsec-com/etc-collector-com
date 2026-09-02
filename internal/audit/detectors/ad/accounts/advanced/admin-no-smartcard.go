package advanced

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminNoSmartcardDetector detects admin accounts without smartcard requirement
type AdminNoSmartcardDetector struct {
	audit.BaseDetector
}

// NewAdminNoSmartcardDetector creates a new detector
func NewAdminNoSmartcardDetector() *AdminNoSmartcardDetector {
	return &AdminNoSmartcardDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_NO_SMARTCARD", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *AdminNoSmartcardDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Must be privileged (adminCount=true)
		if !u.AdminCount {
			continue
		}
		// Must be enabled
		if u.Disabled {
			continue
		}

		// Check SMARTCARD_REQUIRED flag (0x40000)
		smartcardRequired := (u.UserAccountControl & 0x40000) != 0

		if !smartcardRequired {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Admin Account Without Smartcard Requirement",
		Description: "Privileged accounts can authenticate with passwords instead of smartcards. Passwords are more vulnerable to theft and phishing.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Enable 'Smart card is required for interactive logon' for all admin accounts.",
			"benefits": []string{
				"Eliminates password-based attacks (phishing, credential theft)",
				"Provides two-factor authentication",
				"Reduces risk of credential replay attacks",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminNoSmartcardDetector())
}
