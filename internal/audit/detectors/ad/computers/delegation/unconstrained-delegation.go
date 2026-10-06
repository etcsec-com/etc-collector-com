package delegation

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// UnconstrainedDelegationDetector checks for computers with unconstrained delegation
type UnconstrainedDelegationDetector struct {
	audit.BaseDetector
}

// NewUnconstrainedDelegationDetector creates a new detector
func NewUnconstrainedDelegationDetector() *UnconstrainedDelegationDetector {
	return &UnconstrainedDelegationDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_UNCONSTRAINED_DELEGATION", audit.CategoryComputers),
	}
}

// uacServerTrustAccount is the UAC flag for SERVER_TRUST_ACCOUNT (domain
// controllers).
const uacServerTrustAccount = 0x2000

// Detect executes the detection.
//
// Source: Microsoft Learn, "Accounts security posture assessment - Microsoft
// Defender for Identity" (learn.microsoft.com/en-us/defender-for-identity/
// security-posture-assessments/accounts), section "Unsecure Kerberos
// delegation": "...to discover which of your non-domain controller entities
// are configured for unsecure Kerberos delegation." Verified live
// 2026-09-15: the page that originally carried this citation
// (.../security-assessment-unconstrained-kerberos) now redirects here after
// a docs restructuring, and the original wording quoted in an earlier
// version of this comment ("Domain Controllers always have an unconstrained
// delegation set and are not identified as an exposed entity") is no longer
// present verbatim. The substance survives the rewrite: the assessment is
// still scoped to non-domain-controller entities only. DCs need
// unconstrained delegation to function (Kerberos ticket-granting); flagging
// every DC in every domain as a Critical exposure is noise MDI deliberately
// excludes, and this detector now does too.
//
// Account state: split from a single unfiltered detector into an
// active/disabled pair, on the same model as the user-account pair
// (kerberos.UnconstrainedDelegationDetector /
// UnconstrainedDelegationOnDisabledAccountDetector) and the privileged-account
// pair (accounts/privileged.SensitiveDelegationDetector /
// SensitiveDelegationOnDisabledAccountDetector). A computer object CAN be
// disabled: providers/ldap/parser.go sets Computer.Disabled from the same
// UAC_ACCOUNTDISABLE bit as User.Disabled.
//
// A disabled computer account is excluded from THIS detector: measured
// directly against a live KDC, on this exact object class, a disabled
// computer cannot obtain a ticket-granting ticket of its own (closing the
// delegation-origin role) and the KDC will not issue a service ticket for its
// SPN either (closing the delegation-target role) - two separate refusals,
// not one. Both roles become exploitable again the instant the account is
// re-enabled, which is why the disabled population is not dropped but
// reported separately, at Low, by
// UnconstrainedDelegationOnDisabledAccountDetector in this same package. See
// docs/security-validation/results/computer-unconstrained-delegation-disabled-v2/VERDICT.md
// for the measurement.
func (d *UnconstrainedDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.UserAccountControl&uacServerTrustAccount != 0 {
			continue
		}
		if c.Disabled {
			continue
		}
		// c.TrustedForDelegation is the ONLY collected signal for this bit:
		// providers/ldap/parser.go:276 sets it as
		// `computer.TrustedForDelegation = (uac & UAC_TRUSTED_FOR_DELEGATION) != 0`,
		// and there is no second collection path for Computer objects. A
		// prior version of this check read
		// `c.TrustedForDelegation || (c.UserAccountControl & types.UACTrustedForDelegation) != 0`,
		// which is `X || X` on the same field: it read as covering two
		// independent sources but tested the same predicate on the same
		// data twice.
		if c.TrustedForDelegation {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Computer Unconstrained Delegation",
		Description: "Enabled non-domain-controller computer accounts with unconstrained Kerberos delegation enabled (UAC 0x80000). Servers can be used for privilege escalation attacks. Domain controllers are excluded: they always carry unconstrained delegation by design (Microsoft Defender for Identity excludes them from this assessment for the same reason).",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUnconstrainedDelegationDetector())
}
