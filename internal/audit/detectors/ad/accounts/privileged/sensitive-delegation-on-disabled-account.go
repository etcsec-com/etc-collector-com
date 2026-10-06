package privileged

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SensitiveDelegationOnDisabledAccountDetector checks for disabled privileged
// accounts with unconstrained delegation. Split out of
// SensitiveDelegationDetector: a disabled account cannot obtain a TGT
// ([MS-KILE] "Check Account Policy for Every TGT Request" -
// KDC_ERR_CLIENT_REVOKED), so it cannot be used as the ORIGIN of a delegation
// today.
//
// It is ALSO dormant as a TARGET, measured directly against a real KDC
// (Windows Server 2022 Datacenter), not inferred from [MS-KILE] alone: a
// disabled account carrying TRUSTED_FOR_DELEGATION and a real SPN was denied
// a service ticket (0x6fb/0xc000018b) on every attempt, identically to a
// disabled account without the bit, and the ticket was issued again within
// seconds of re-enabling the same object with no other change. The refusal
// happens before OK-AS-DELEGATE or the SPN's class can matter, so there is no
// SPN / no-SPN distinction left to draw here: both are equally inert while
// the account is disabled, privileged group membership notwithstanding. The
// configuration itself is not removed by this state - it persists on disk
// and reasserts full exploitability against a privileged account the instant
// it is re-enabled, which is the residual risk this detector keeps
// reporting. Full measurement, methodology and the two independent
// executions (executor and verifier, the latter's contestation of the
// original ticket's scope being why this file is covered too) in
// docs/security-validation/results/unconstrained-delegation-disabled-v2/VERDICT.md
// and
// docs/security-validation/verifications/unconstrained-delegation-disabled-v2/VERDICT-security.md,
// which supersede the [MS-KILE]-reading-only argument previously cited here.
// Same convention as
// UNCONSTRAINED_DELEGATION_ON_DISABLED_ACCOUNT and
// PASSWORD_NOT_REQUIRED_ON_DISABLED_ACCOUNT: the suffix names the population
// covered, not the state of a mechanism - _DISABLED alone is reserved
// elsewhere in this catalog for "a protection was turned off".
type SensitiveDelegationOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewSensitiveDelegationOnDisabledAccountDetector creates a new detector
func NewSensitiveDelegationOnDisabledAccountDetector() *SensitiveDelegationOnDisabledAccountDetector {
	return &SensitiveDelegationOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("SENSITIVE_DELEGATION_ON_DISABLED_ACCOUNT", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *SensitiveDelegationOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	privilegedDNs := privilegedGroupDNsBySID(data)

	for _, u := range data.Users {
		if !u.Disabled {
			continue
		}

		if len(u.MemberOf) == 0 {
			continue
		}

		hasUnconstrainedDeleg := (u.UserAccountControl & types.UACTrustedForDelegation) != 0

		if !hasUnconstrainedDeleg {
			continue
		}

		if isMemberOfPrivilegedGroup(u.MemberOf, privilegedDNs) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Sensitive Account with Delegation (Disabled Account)",
		Description: "Disabled privileged accounts (Domain Admins, Domain Controllers, Schema Admins, Enterprise Admins, Key Admins, Enterprise Key Admins, Administrators, Account Operators, Server Operators, Print Operators, Backup Operators) with unconstrained delegation are not exploitable while disabled. Two separate refusals apply: the account cannot obtain a ticket-granting ticket of its own, which closes the delegation-origin role, and the KDC will not issue a service ticket for its SPN, which closes the delegation-target role. The configuration remains set, and both roles become exploitable again against a privileged account the instant it is re-enabled. Remediation: remove the delegation bit or delete the account.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSensitiveDelegationOnDisabledAccountDetector())
}
