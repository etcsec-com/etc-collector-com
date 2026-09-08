package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// workstationTrustAccount is the UAC flag marking a workstation/member-server
// trust account, as opposed to a domain-controller trust account.
const workstationTrustAccount = 0x1000

// preCreatedUAC is UAC 4128: PASSWD_NOTREQD + WORKSTATION_TRUST_ACCOUNT. A
// computer account pre-staged (e.g. via netdom, or the "assign this computer
// account" AD Users & Computers wizard) carries exactly this combination
// until the machine actually joins and sets its own password - the account
// is active throughout, so Disabled is not part of the definition.
const preCreatedUAC = types.UACPasswordNotRequired | workstationTrustAccount

// PreCreatedDetector checks for pre-created (staging) computer accounts
type PreCreatedDetector struct {
	audit.BaseDetector
}

// NewPreCreatedDetector creates a new detector
func NewPreCreatedDetector() *PreCreatedDetector {
	return &PreCreatedDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_PRE_CREATED", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *PreCreatedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.UserAccountControl&preCreatedUAC == preCreatedUAC {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Computer Pre-Created (Staging)",
		Description: "Computer accounts with UAC flags PASSWD_NOTREQD and WORKSTATION_TRUST_ACCOUNT set. These are staging accounts pre-created but not yet joined to the domain. Should be reviewed and cleaned up.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPreCreatedDetector())
}
