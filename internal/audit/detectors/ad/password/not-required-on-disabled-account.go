package password

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NotRequiredOnDisabledAccountDetector checks for disabled accounts that do
// not require a password. Split out of NotRequiredDetector: a disabled
// account cannot authenticate, so the missing password-length enforcement on
// it is not usable today - but the configuration survives a re-enable, so it
// stays reported, at a severity that reflects dormancy rather than active
// risk. Same convention as UNCONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT and
// PASSWORD_NEVER_EXPIRES_ON_DISABLED_ACCOUNT: the suffix names the
// population covered, not the state of a mechanism - _DISABLED alone is
// reserved elsewhere in this catalog for "a protection was turned off".
type NotRequiredOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewNotRequiredOnDisabledAccountDetector creates a new detector
func NewNotRequiredOnDisabledAccountDetector() *NotRequiredOnDisabledAccountDetector {
	return &NotRequiredOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_NOT_REQUIRED_ON_DISABLED_ACCOUNT", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *NotRequiredOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		// Windows sets PASSWD_NOTREQD (0x20) on every interdomain trust
		// account by default; its secret is managed by the system, not a
		// human (KB 305144), so it is excluded here rather than flagged.
		if (u.UserAccountControl & types.UACInterdomainTrustAccount) != 0 {
			continue
		}
		if (u.UserAccountControl & types.UACPasswordNotRequired) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityLow,
		Category: string(d.Category()),
		Title:    "Password Not Required (Disabled Account)",
		// MS-ADTS 2.2.16 (bit NR, 0x20): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd302fd1-0aa7-406b-ad91-2a6b35738557
		// The bit only lifts the password-length policy; it does not prove
		// the password is actually empty, which this collector does not read.
		Description: "Disabled user accounts where the password-length policy does not apply (UAC flag 0x20, MS-ADTS 2.2.16). Not usable while disabled, but the configuration survives a re-enable, and this detector does not read whether the current password actually is empty. Interdomain trust accounts (UAC flag 0x800) are excluded: Windows sets this flag on them by default (KB 305144).",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNotRequiredOnDisabledAccountDetector())
}
