package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminCountDetector checks for computers with adminCount attribute set to
// 1.
//
// Disabled computers are excluded here: a disabled computer account cannot
// authenticate, so adminCount residue on it reflects former privilege
// rather than a live administrative surface. SDProp/AdminSDHolder does not
// clear adminCount when an account is disabled, so the exposure does not go
// away - it stays reported, at the same Info severity (already the
// catalog's lowest - unlike the High-to-Low splits elsewhere in this wave,
// there is no lower rung to step down to), by
// AdminCountOnDisabledAccountDetector (see
// admin-count-on-disabled-account.go): it would matter again if the account
// is re-enabled.
type AdminCountDetector struct {
	audit.BaseDetector
}

// NewAdminCountDetector creates a new detector
func NewAdminCountDetector() *AdminCountDetector {
	return &AdminCountDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_ADMIN_COUNT", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *AdminCountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.Disabled {
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
		Title:       "Computer adminCount Set",
		Description: "Computer with adminCount attribute set to 1. May indicate current or former administrative privileges.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminCountDetector())
}
