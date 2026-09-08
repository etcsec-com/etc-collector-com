package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnconstrainedDelegationDetector checks for accounts with unconstrained Kerberos delegation
type UnconstrainedDelegationDetector struct {
	audit.BaseDetector
}

// NewUnconstrainedDelegationDetector creates a new detector
func NewUnconstrainedDelegationDetector() *UnconstrainedDelegationDetector {
	return &UnconstrainedDelegationDetector{
		BaseDetector: audit.NewBaseDetector("UNCONSTRAINED_DELEGATION", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *UnconstrainedDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if (user.UserAccountControl & types.UACTrustedForDelegation) != 0 {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Unconstrained Delegation",
		Description: "User accounts with unconstrained Kerberos delegation enabled (UAC 0x80000). Can impersonate any user.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUnconstrainedDelegationDetector())
}
