package other

import (
	"context"
	"time"

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

// Detect executes the detection.
//
// Source: [MS-ADA2] 2.344 msDS-ExpirePasswordsOnSmartCardOnlyAccounts
// (learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/1ba3e699-77ab-4ba6-9d70-74616b1e11d4),
// requires DFL Windows Server 2016+. This is the real domain-level control
// the detector's name refers to: when it is not enabled (the default -
// nothing in this codebase or a fresh domain ever turns it on by itself),
// DCs issue UF_SMARTCARD_REQUIRED accounts a random password and never
// rotate it, by design - this is not a staleness anomaly to infer from
// pwdLastSet, it is AD's documented default behavior, and is now read
// directly instead of guessed at.
//
// When the domain HAS enabled the knob, rotation should be happening on the
// domain's actual password policy - so staleness is compared against
// data.DomainInfo.MaxPasswordAge (the real maxPwdAge, already collected),
// never a hardcoded day count: no official source ties this feature to any
// fixed number of days (a previously-cited "90 days" - and a competing
// third-party "60 days" - were both product assumptions, not standards
// requirements). Without a real policy to compare against (MaxPasswordAge
// == 0, e.g. "passwords never expire" domain-wide, itself a separate
// finding) there is no schedule to be behind on, so nothing is inferred.
func (d *SmartcardRotationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		// Domain policy was never measured - firing here would punish every
		// client we simply couldn't query, not one with a real gap.
		return []types.Finding{{
			Type:        d.ID(),
			Severity:    types.SeverityMedium,
			Category:    string(d.Category()),
			Title:       "Smart Card Password Rotation Disabled",
			Description: "Smart card users have passwords that haven't been rotated. When smart card password rotation is disabled, the underlying password remains static, making the account vulnerable if the password hash is compromised.",
			Count:       0,
		}}
	}

	knobEnabled := data.DomainInfo.ExpirePasswordsOnSmartCardOnlyAccounts
	var policyThreshold time.Time
	hasPolicyThreshold := data.DomainInfo.MaxPasswordAge > 0
	if hasPolicyThreshold {
		policyThreshold = data.Now.AddDate(0, 0, -data.DomainInfo.MaxPasswordAge)
	}

	var affected []types.User
	for _, user := range data.Users {
		// Only check enabled users with SMARTCARD_REQUIRED flag set
		if user.Disabled {
			continue
		}
		if (user.UserAccountControl & smartcardRequiredFlag) == 0 {
			continue
		}

		if !knobEnabled {
			// Domain design gap: this account's password is never rotated,
			// regardless of how recently pwdLastSet was touched.
			affected = append(affected, user)
			continue
		}

		if hasPolicyThreshold && (user.PasswordLastSet.IsZero() || user.PasswordLastSet.Before(policyThreshold)) {
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
