package password

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NotRequiredDetector detects enabled accounts that do not require a
// password. Scoped to active accounts: a disabled account cannot
// authenticate, so the missing password-length enforcement on it is not
// usable today - see NotRequiredOnDisabledAccountDetector for the
// disabled-account claim, reported separately at Low.
type NotRequiredDetector struct {
	audit.BaseDetector
}

// NewNotRequiredDetector creates a new detector
func NewNotRequiredDetector() *NotRequiredDetector {
	return &NotRequiredDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_NOT_REQUIRED", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *NotRequiredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if u.Disabled {
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
		Severity: types.SeverityCritical,
		Category: string(d.Category()),
		Title:    "Password Not Required",
		// MS-ADTS 2.2.16 (bit NR, 0x20): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd302fd1-0aa7-406b-ad91-2a6b35738557
		// The bit only lifts the password-length policy; it does not prove
		// the password is actually empty, which this collector does not read.
		Description: "Enabled user accounts where the password-length policy does not apply (UAC flag 0x20, MS-ADTS 2.2.16): the account can be assigned an empty password, but this detector does not read whether the current password actually is one. Interdomain trust accounts (UAC flag 0x800) are excluded: Windows sets this flag on them by default, and their secret is managed by the system (KB 305144).",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNotRequiredDetector())
}
