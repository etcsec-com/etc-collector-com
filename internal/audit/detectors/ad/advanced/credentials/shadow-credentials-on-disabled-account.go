package credentials

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ShadowCredentialsOnDisabledAccountDetector checks for disabled user and
// computer accounts carrying msDS-KeyCredentialLink. Split out of
// ShadowCredentialsDetector: UF_ACCOUNTDISABLE blocks authentication for the
// account across every protocol (interactive logon, LDAP bind, NTLM,
// Kerberos, and therefore PKINIT), so a shadow-credential key on a disabled
// account cannot be used to authenticate as that account today. The
// exposure itself does not go away - the key credential is still readable
// on the object by anyone who can read the attribute - so it stays
// reported, at a severity that reflects dormancy rather than active risk,
// for when the account is re-enabled.
//
// Named SHADOW_CREDENTIALS_ON_DISABLED_ACCOUNT, not
// SHADOW_CREDENTIALS_DISABLED: the _DISABLED suffix is reserved elsewhere in
// this catalog for "a protection was turned off" (LDAP_SIGNING_DISABLED,
// TRUST_AES_DISABLED, ...), which reads as bad news. Naming the population
// instead of a mechanism state avoids an auditor misreading this as the
// risk itself being off.
//
// Specificity: SHADOW_CREDENTIALS has two populations, User and Computer -
// unlike the single-branch splits elsewhere in this wave. Both branches
// below mirror shadow-credentials.go's active detector, each with its own
// Disabled guard (inverted: only disabled carriers count here).
type ShadowCredentialsOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewShadowCredentialsOnDisabledAccountDetector creates a new detector
func NewShadowCredentialsOnDisabledAccountDetector() *ShadowCredentialsOnDisabledAccountDetector {
	return &ShadowCredentialsOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("SHADOW_CREDENTIALS_ON_DISABLED_ACCOUNT", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *ShadowCredentialsOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedUsers []types.User
	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}
		if len(u.KeyCredentialLink) > 0 {
			affectedUsers = append(affectedUsers, u)
		}
	}

	var affectedComputers []types.Computer
	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		if len(c.KeyCredentialLink) > 0 {
			affectedComputers = append(affectedComputers, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Shadow Credentials (Disabled Account)",
		Description: "msDS-KeyCredentialLink is configured on a disabled user or computer account. Not usable to authenticate today - UF_ACCOUNTDISABLE blocks authentication across every protocol, including PKINIT - but the key credential remains readable on the object and would matter again if the account is re-enabled.",
		Count:       len(affectedUsers) + len(affectedComputers),
	}

	if data.IncludeDetails && (len(affectedUsers) > 0 || len(affectedComputers) > 0) {
		entities := make([]types.AffectedEntity, 0, len(affectedUsers)+len(affectedComputers))
		entities = append(entities, helpers.ToAffectedUserEntities(affectedUsers)...)
		entities = append(entities, helpers.ToAffectedComputerEntities(affectedComputers)...)
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewShadowCredentialsOnDisabledAccountDetector())
}
