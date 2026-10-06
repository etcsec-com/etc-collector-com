package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WeakEncryptionDESOnDisabledAccountDetector checks for disabled accounts
// with DES encryption enabled (UAC USE_DES_KEY_ONLY and/or
// msDS-SupportedEncryptionTypes DES bits). Split out of
// WeakEncryptionDESDetector.
//
// Dormant for two independent [MS-KILE] reasons that combine, neither one
// substituting for the other:
//
//   - CLIENT role: "Check Account Policy for Every TGT Request" returns
//     KDC_ERR_CLIENT_REVOKED at AS-REQ for a disabled account, so it cannot
//     reach the initial exchange where DES could be negotiated at all - not
//     even on the USE_DES_KEY_ONLY branch, which WOULD complete a
//     DES-encrypted AS exchange for this same account if it were active
//     (see WeakEncryptionDESDetector's own Detect comment: that branch is
//     exactly why the active half is High rather than merely
//     configured-but-inert).
//   - TARGET role: "TGS Exchange" refuses DES unconditionally
//     (KDC_ERR_ETYPE_NOTSUPP) for any service ticket requested against this
//     account, independent of its enabled state - this path was never live
//     either way, active or disabled.
//
// An environment whose domain controller does not carry DES in its Kerberos
// encryption policy reinforces the conclusion further, but is not itself
// what makes this half dormant: the CLIENT-role argument above holds
// regardless of what the KDC's own policy allows, because a disabled
// account can never reach AS-REQ to test it. The configuration persists on
// disk and stays reported, at a severity that reflects dormancy rather than
// active risk, for when the account is re-enabled.
//
// Named WEAK_ENCRYPTION_DES_ON_DISABLED_ACCOUNT, not
// WEAK_ENCRYPTION_DES_DISABLED: the _DISABLED suffix is reserved elsewhere in
// this catalog for "a protection was turned off" (LDAP_SIGNING_DISABLED,
// TRUST_AES_DISABLED, ...), which reads as bad news. Naming the population
// instead of a mechanism state avoids an auditor misreading this as the risk
// itself being off.
type WeakEncryptionDESOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewWeakEncryptionDESOnDisabledAccountDetector creates a new detector
func NewWeakEncryptionDESOnDisabledAccountDetector() *WeakEncryptionDESOnDisabledAccountDetector {
	return &WeakEncryptionDESOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("WEAK_ENCRYPTION_DES_ON_DISABLED_ACCOUNT", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *WeakEncryptionDESOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if !user.Disabled {
			continue
		}

		if (user.UserAccountControl & uacUseDESKeyOnly) != 0 {
			affected = append(affected, user)
			continue
		}

		// No `> 0` guard: see WeakEncryptionDESDetector.Detect for why the
		// DES bit mask alone is sufficient even on a negative value.
		if (user.SupportedEncryptionTypes & desTypes) != 0 {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Weak DES Encryption (Disabled Account)",
		Description: "Disabled user accounts with DES encryption algorithms enabled (UAC 0x200000 and/or msDS-SupportedEncryptionTypes). Dormant for two combined reasons: as a client, a disabled account cannot complete the initial Kerberos exchange (AS-REQ) where DES could actually be negotiated, even on the branch that would succeed if the account were active; as a target, a service ticket requested by a third party against this account can never be protected with DES regardless of its enabled state, since the KDC categorically refuses DES for service tickets. A domain controller whose Kerberos encryption policy does not include DES reinforces this further, but is not itself the reason the disabled half stays dormant. The configuration remains set and stays reported for when the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakEncryptionDESOnDisabledAccountDetector())
}
