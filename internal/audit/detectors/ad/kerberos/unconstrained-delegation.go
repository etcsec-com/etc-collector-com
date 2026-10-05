package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnconstrainedDelegationDetector checks for accounts with unconstrained
// Kerberos delegation. Scoped to active accounts: a disabled account can
// obtain neither its own ticket-granting ticket ([MS-KILE] "Check Account
// Policy for Every TGT Request" - KDC_ERR_CLIENT_REVOKED), which closes the
// delegation-ORIGIN role, nor - measured directly against a live KDC - a
// service ticket toward its own SPN on a third party's behalf, which closes
// the delegation-TARGET role too. Both refusals lift the instant the account
// is re-enabled, which is why that disabled population is not dropped but
// reported separately, at Low, by
// UnconstrainedDelegationOnDisabledAccountDetector. Full measurement in
// docs/security-validation/results/unconstrained-delegation-disabled-v2/VERDICT.md.
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
		if user.Disabled {
			continue
		}
		if (user.UserAccountControl & types.UACTrustedForDelegation) != 0 {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Unconstrained Delegation",
		Description: "Enabled user accounts with unconstrained Kerberos delegation enabled (UAC 0x80000). Can impersonate any user.",
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
