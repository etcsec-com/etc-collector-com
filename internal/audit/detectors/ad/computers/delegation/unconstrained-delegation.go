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
// Source: Microsoft Learn, "Unsecure Kerberos delegation assessment -
// Microsoft Defender for Identity" (learn.microsoft.com/en-us/defender-for-identity/
// security-assessment-unconstrained-kerberos): "Domain Controllers always
// have an unconstrained delegation set and are not identified [by MDI] as
// an exposed entity." DCs need unconstrained delegation to function
// (Kerberos ticket-granting); flagging every DC in every domain as a
// Critical exposure is noise MDI deliberately excludes, and this detector now does too.
func (d *UnconstrainedDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.UserAccountControl&uacServerTrustAccount != 0 {
			continue
		}
		if c.TrustedForDelegation || (c.UserAccountControl&types.UACTrustedForDelegation) != 0 {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Computer Unconstrained Delegation",
		Description: "Non-domain-controller computer with unconstrained delegation enabled. Servers can be used for privilege escalation attacks. Domain controllers are excluded: they always carry unconstrained delegation by design (Microsoft Defender for Identity excludes them from this assessment for the same reason).",
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
