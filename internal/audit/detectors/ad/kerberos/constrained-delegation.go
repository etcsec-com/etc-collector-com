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
func (d *ConstrainedDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		// The UAC bit only marks constrained delegation WITH protocol
		// transition (S4U2Self + S4U2Proxy). Classic Kerberos-only constrained
		// delegation (S4U2Proxy alone) never sets it — it is identified
		// exclusively by msDS-AllowedToDelegateTo being non-empty, exactly how
		// the already-verified COMPUTER_CONSTRAINED_DELEGATION reads it for
		// computers (T_090/B_012).
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
