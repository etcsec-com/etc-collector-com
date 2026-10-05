package gpo

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DisabledButLinkedDetector checks for disabled GPOs that are still linked
type DisabledButLinkedDetector struct {
	audit.BaseDetector
}

// NewDisabledButLinkedDetector creates a new detector
func NewDisabledButLinkedDetector() *DisabledButLinkedDetector {
	return &DisabledButLinkedDetector{
		BaseDetector: audit.NewBaseDetector("GPO_DISABLED_BUT_LINKED", audit.CategoryGPO),
	}
}

// GPO flags on the groupPolicyContainer's "flags" attribute. Source: the
// values are the four states GPMC/Get-ADObject expose for this attribute -
// 0 = User Enabled/Computer Enabled, 1 = User Disabled/Computer Enabled,
// 2 = User Enabled/Computer Disabled, 3 = User Disabled/Computer Disabled
// (see Microsoft's "Use PowerShell to Get GPO Status Flag", which encodes
// exactly these four constants against the flags attribute). flags=3 is
// confirmed empirically too: Get-GPO's GpoStatus reads back "AllSettingsDisabled"
// for a GPO planted with flags=3 (see docs/security-validation/results/t163-manual/VERDICT-T163.md).
const gpoFlagAllDisabled = 3 // Both user and computer settings disabled

// Detect executes the detection
func (d *DisabledButLinkedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.GPO

	// Find GPOs that are disabled (flags = 3) but have active links
	for _, gpo := range data.GPOs {
		if gpo.Flags != gpoFlagAllDisabled {
			continue
		}

		// Check if this GPO has active links
		for _, link := range data.GPOLinks {
			if strings.EqualFold(link.GPOCN, gpo.CN) && link.LinkEnabled {
				affected = append(affected, gpo)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Disabled GPO Still Linked",
		Description: "GPOs are disabled (both user and computer settings) but remain linked. This may indicate configuration drift or incomplete changes.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGPOEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDisabledButLinkedDetector())
}
