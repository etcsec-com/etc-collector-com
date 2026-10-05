package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ConstrainedDelegationOnDisabledAccountDetector checks for disabled accounts
// with constrained Kerberos delegation configured. Split out of
// ConstrainedDelegationDetector: per [MS-SFU], both the protocol-transition
// branch (S4U2Self, gated by the TRUSTED_TO_AUTH_FOR_DELEGATION UAC bit) and
// the classic Kerberos-only branch (S4U2Proxy alone, gated by
// msDS-AllowedToDelegateTo) are sent as a KRB_TGS_REQ that requires the
// delegating account's own valid TGT. Per [MS-KILE] "Check Account Policy for
// Every TGT Request", a disabled account cannot obtain a new TGT
// (KDC_ERR_CLIENT_REVOKED at AS-REQ), so neither branch is exploitable from
// this account today - but the configuration persists on disk and would
// matter again the moment the account is re-enabled, so it stays reported, at
// a severity that reflects dormancy rather than active risk.
//
// Named CONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT, not
// CONSTRAINED_DELEGATION_DISABLED: the _DISABLED suffix is reserved elsewhere
// in this catalog for "a protection was turned off" (LDAP_SIGNING_DISABLED,
// TRUST_AES_DISABLED, ...), which reads as bad news. Naming the population
// instead of a mechanism state avoids an auditor misreading this as the risk
// itself being off.
type ConstrainedDelegationOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewConstrainedDelegationOnDisabledAccountDetector creates a new detector
func NewConstrainedDelegationOnDisabledAccountDetector() *ConstrainedDelegationOnDisabledAccountDetector {
	return &ConstrainedDelegationOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("CONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *ConstrainedDelegationOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if !user.Disabled {
			continue
		}

		hasProtocolTransition := (user.UserAccountControl & types.UACTrustedToAuthForDelegation) != 0
		hasDelegationTargets := len(user.AllowedToDelegateTo) > 0

		if hasProtocolTransition || hasDelegationTargets {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Constrained Delegation (Disabled Account)",
		Description: "Disabled user accounts with constrained Kerberos delegation configured (UAC 0x1000000 and/or msDS-AllowedToDelegateTo). Not exploitable while disabled - obtaining the TGT that either delegation path requires is blocked at AS-REQ - but the configuration remains set and would apply again if the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewConstrainedDelegationOnDisabledAccountDetector())
}
