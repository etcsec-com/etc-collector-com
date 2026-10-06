package security

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WithSPNsDetector checks for computers with SPNs (Kerberoastable)
type WithSPNsDetector struct {
	audit.BaseDetector
}

// NewWithSPNsDetector creates a new detector
func NewWithSPNsDetector() *WithSPNsDetector {
	return &WithSPNsDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_WITH_SPNS", audit.CategoryComputers),
	}
}

// Detect executes the detection.
//
// A prior version's premise ("Enables Kerberoasting attack against computer
// account", High) contradicts how Kerberoasting actually works. Computer
// account passwords are 120-character, cryptographically random, and
// rotated automatically by the domain (every 30 days by default) - they are
// not practically crackable offline the way a human-chosen service-account
// password is. Microsoft's own Kerberoasting mitigation guidance targets
// (g)MSA and user service accounts, not computer accounts (Microsoft
// Security Blog, "Microsoft's guidance to help mitigate Kerberoasting",
// Oct 2024 - microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/).
// In production this fired as High on nearly every computer with an SPN -
// pure noise, not a viable attack path. Retitled and downgraded to Info: an
// inventory signal, not a Kerberoasting exposure claim.
func (d *WithSPNsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if len(c.ServicePrincipalNames) > 0 {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Computer with Service Principal Names",
		Description: "Computer account has Service Principal Names registered. Unlike user service accounts, computer account passwords are long, random, and automatically rotated by the domain, making offline Kerberoasting impractical against them - this is an inventory signal, not a confirmed attack path.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWithSPNsDetector())
}
