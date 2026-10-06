package delegation

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnconstrainedDelegationOnDisabledAccountDetector checks for disabled
// non-domain-controller computer accounts with unconstrained Kerberos
// delegation. Split out of UnconstrainedDelegationDetector, on the same model
// as the user-account pair (kerberos.UnconstrainedDelegationDetector /
// UnconstrainedDelegationOnDisabledAccountDetector) and the privileged-account
// pair (accounts/privileged.SensitiveDelegationDetector /
// SensitiveDelegationOnDisabledAccountDetector): a disabled computer account
// cannot obtain a ticket-granting ticket of its own, which closes the
// delegation-origin role, and the KDC will not issue a service ticket for its
// SPN either, which closes the delegation-target role - two separate
// refusals, both measured directly against a live KDC, on this exact object
// class, not inferred from documentation alone. The configuration itself is
// not removed by this state - it persists and reasserts full exploitability
// the instant the account is re-enabled, which is the residual risk this
// detector keeps reporting. Full measurement, methodology and the two
// independent executions (executor and verifier) in
// docs/security-validation/results/computer-unconstrained-delegation-disabled-v2/VERDICT.md.
// Same convention as UNCONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT and
// SENSITIVE_DELEGATION_ON_DISABLED_ACCOUNT: the suffix names the population
// covered, not the state of a mechanism - _DISABLED alone is reserved
// elsewhere in this catalog for "a protection was turned off".
type UnconstrainedDelegationOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewUnconstrainedDelegationOnDisabledAccountDetector creates a new detector
func NewUnconstrainedDelegationOnDisabledAccountDetector() *UnconstrainedDelegationOnDisabledAccountDetector {
	return &UnconstrainedDelegationOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_UNCONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *UnconstrainedDelegationOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.UserAccountControl&uacServerTrustAccount != 0 {
			continue
		}
		if !c.Disabled {
			continue
		}
		if c.TrustedForDelegation {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Computer Unconstrained Delegation (Disabled Account)",
		Description: "Disabled non-domain-controller computer accounts with unconstrained Kerberos delegation enabled (UAC 0x80000) are not exploitable while disabled. Two separate refusals apply: the account cannot obtain a ticket-granting ticket of its own, which closes the delegation-origin role, and the KDC will not issue a service ticket for its SPN, which closes the delegation-target role. The configuration remains set, and both roles become exploitable again the instant the account is re-enabled. Domain controllers are excluded: they always carry unconstrained delegation by design (Microsoft Defender for Identity excludes them from this assessment for the same reason). Remediation: remove the delegation bit or delete the account.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUnconstrainedDelegationOnDisabledAccountDetector())
}
