package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminCountOnDisabledAccountDetector checks for disabled computer accounts
// carrying the adminCount attribute. Split out of AdminCountDetector: a
// disabled computer account cannot authenticate, so adminCount residue on
// it reflects former privilege rather than a live administrative surface.
// SDProp/AdminSDHolder does not clear adminCount when an account is
// disabled, so the exposure does not go away - it stays reported, at Info
// (the catalog's lowest severity; there is no lower rung to step down to,
// unlike the High-to-Low splits elsewhere in this wave), for when the
// account is re-enabled.
//
// Named COMPUTER_ADMIN_COUNT_ON_DISABLED_ACCOUNT, not
// COMPUTER_ADMIN_COUNT_DISABLED: the _DISABLED suffix is reserved elsewhere
// in this catalog for "a protection was turned off" (LDAP_SIGNING_DISABLED,
// TRUST_AES_DISABLED, ...), which reads as bad news. Naming the population
// instead of a mechanism state avoids an auditor misreading this as the
// risk itself being off.
type AdminCountOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewAdminCountOnDisabledAccountDetector creates a new detector
func NewAdminCountOnDisabledAccountDetector() *AdminCountOnDisabledAccountDetector {
	return &AdminCountOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_ADMIN_COUNT_ON_DISABLED_ACCOUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *AdminCountOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if !c.Disabled {
			continue
		}
		if c.AdminCount {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Computer adminCount Set (Disabled Account)",
		Description: "Disabled computer account with adminCount attribute set to 1. Not a live administrative surface - the account cannot authenticate - but the residue indicates current or former administrative privileges and would matter again if the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminCountOnDisabledAccountDetector())
}
