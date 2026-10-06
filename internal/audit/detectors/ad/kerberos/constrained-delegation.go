package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ConstrainedDelegationDetector checks for accounts with constrained Kerberos delegation
type ConstrainedDelegationDetector struct {
	audit.BaseDetector
}

// NewConstrainedDelegationDetector creates a new detector
func NewConstrainedDelegationDetector() *ConstrainedDelegationDetector {
	return &ConstrainedDelegationDetector{
		BaseDetector: audit.NewBaseDetector("CONSTRAINED_DELEGATION", audit.CategoryKerberos),
	}
}

// Detect executes the detection
//
// Disabled accounts are excluded here on purpose, on BOTH branches below: per
// [MS-SFU], both S4U2Self (protocol transition) and S4U2Proxy (classic
// Kerberos-only) are sent as a KRB_TGS_REQ that requires the delegating
// account's own valid TGT, and per [MS-KILE] "Check Account Policy for Every
// TGT Request" a disabled account cannot obtain a new TGT (KDC_ERR_CLIENT_REVOKED
// at AS-REQ). It is not dropped from the audit -
// ConstrainedDelegationOnDisabledAccountDetector reports it at Low, since the
// configuration persists and would matter again the moment the account is
// re-enabled.
func (d *ConstrainedDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if user.Disabled {
			continue
		}

		// The UAC bit only marks constrained delegation WITH protocol
		// transition (S4U2Self + S4U2Proxy). Classic Kerberos-only constrained
		// delegation (S4U2Proxy alone) never sets it - it is identified
		// exclusively by msDS-AllowedToDelegateTo being non-empty, the same
		// attribute test COMPUTER_CONSTRAINED_DELEGATION uses for computers
		// elsewhere in this catalogue (that detector is its own, unverified,
		// finding - not established by this one).
		hasProtocolTransition := (user.UserAccountControl & types.UACTrustedToAuthForDelegation) != 0
		hasDelegationTargets := len(user.AllowedToDelegateTo) > 0

		if hasProtocolTransition || hasDelegationTargets {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Constrained Delegation",
		Description: "User accounts with constrained Kerberos delegation configured (UAC 0x1000000). Can impersonate users to specific services.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewConstrainedDelegationDetector())
}
