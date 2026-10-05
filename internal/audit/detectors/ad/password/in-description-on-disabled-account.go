package password

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PasswordInDescriptionOnDisabledAccountDetector checks for disabled
// accounts with a password or password-like string in the description
// field. Split out of InDescriptionDetector: UF_ACCOUNTDISABLE blocks
// authentication for this account across every protocol (interactive logon,
// LDAP bind, NTLM, Kerberos), so the leaked credential cannot be used to log
// on as this account today. The exposure itself does not go away - the
// plaintext value is still readable on the object by anyone who can read the
// attribute - so it stays reported, at a severity that reflects dormancy
// rather than active risk, for when the account is re-enabled.
//
// Named PASSWORD_IN_DESCRIPTION_ON_DISABLED_ACCOUNT, not
// PASSWORD_IN_DESCRIPTION_DISABLED: the _DISABLED suffix is reserved
// elsewhere in this catalog for "a protection was turned off"
// (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED, ...), which reads as bad news.
// Naming the population instead of a mechanism state avoids an auditor
// misreading this as the risk itself being off.
type PasswordInDescriptionOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewPasswordInDescriptionOnDisabledAccountDetector creates a new detector
func NewPasswordInDescriptionOnDisabledAccountDetector() *PasswordInDescriptionOnDisabledAccountDetector {
	return &PasswordInDescriptionOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_IN_DESCRIPTION_ON_DISABLED_ACCOUNT", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *PasswordInDescriptionOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User
	// matchedPatterns[i] holds the pattern names for affected[i], same
	// contract as InDescriptionDetector: name the credential's shape, never
	// carry the value.
	var matchedPatterns [][]string

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}

		if names := types.MatchSecretPatterns(u.Description); len(names) > 0 {
			affected = append(affected, u)
			matchedPatterns = append(matchedPatterns, names)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Password in Description (Disabled Account)",
		Description: "Disabled user accounts with passwords or password-like strings in the description field. Not usable to log on today - UF_ACCOUNTDISABLE blocks authentication for this account across every protocol - but the plaintext value remains readable on the object and would matter again if the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		entities := helpers.ToAffectedUserEntities(affected)
		for i := range entities {
			entities[i].Description = "matched credential pattern: " + strings.Join(matchedPatterns[i], ", ")
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPasswordInDescriptionOnDisabledAccountDetector())
}
