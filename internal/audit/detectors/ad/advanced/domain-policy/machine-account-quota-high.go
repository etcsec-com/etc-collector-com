package domainpolicy

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const defaultMachineQuota = 10

// MachineAccountQuotaHighDetector detects elevated machine account quota
type MachineAccountQuotaHighDetector struct {
	audit.BaseDetector
}

// NewMachineAccountQuotaHighDetector creates a new detector
func NewMachineAccountQuotaHighDetector() *MachineAccountQuotaHighDetector {
	return &MachineAccountQuotaHighDetector{
		BaseDetector: audit.NewBaseDetector("MACHINE_ACCOUNT_QUOTA_HIGH", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *MachineAccountQuotaHighDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return []types.Finding{{
			Type:        d.ID(),
			Severity:    types.SeverityHigh,
			Category:    string(d.Category()),
			Title:       "Machine Account Quota Elevated Above Default",
			Description: "Unable to check machine account quota.",
			Count:       0,
		}}
	}

	quota := data.DomainInfo.MachineAccountQuota
	isElevated := quota > defaultMachineQuota

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Machine Account Quota Elevated Above Default",
		Description: "ms-DS-MachineAccountQuota is higher than the default (10). Someone intentionally increased this value, allowing non-admin users to join more computers to the domain.",
		Count:       0,
	}

	if isElevated {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{types.DomainInfoToAffectedEntity(data.DomainInfo)}
			finding.Details = map[string]interface{}{
				"currentQuota":   quota,
				"defaultQuota":   defaultMachineQuota,
				"recommendation": "Set ms-DS-MachineAccountQuota to 0 to prevent non-admin domain joins.",
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMachineAccountQuotaHighDetector())
}
