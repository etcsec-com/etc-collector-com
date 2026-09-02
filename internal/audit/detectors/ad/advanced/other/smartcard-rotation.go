package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UAC flag 0x40000 = SMARTCARD_REQUIRED
const smartcardRequiredFlag = 0x40000

// SmartcardRotationDetector checks for smart card users whose passwords haven't been rotated
type SmartcardRotationDetector struct {
	audit.BaseDetector
}

// NewSmartcardRotationDetector creates a new detector
func NewSmartcardRotationDetector() *SmartcardRotationDetector {
	return &SmartcardRotationDetector{
		BaseDetector: audit.NewBaseDetector("SMARTCARD_PASSWORD_ROTATION_DISABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *SmartcardRotationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	now := data.Now
	threshold := now.AddDate(0, 0, -90) // 90 days ago

	var affected []types.User
	for _, user := range data.Users {
		// Only check enabled users with SMARTCARD_REQUIRED flag set
		if user.Disabled {
			continue
		}
		if (user.UserAccountControl & smartcardRequiredFlag) == 0 {
			continue
		}

		// If PasswordLastSet is zero or older than 90 days, the password is not being rotated
		if user.PasswordLastSet.IsZero() || user.PasswordLastSet.Before(threshold) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Smart Card Password Rotation Disabled",
		Description: "Smart card users have passwords that haven't been rotated. When smart card password rotation is disabled, the underlying password remains static, making the account vulnerable if the password hash is compromised.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSmartcardRotationDetector())
}
