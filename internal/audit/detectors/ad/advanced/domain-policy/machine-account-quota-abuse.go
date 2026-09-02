package domainpolicy

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// MachineAccountQuotaAbuseDetector detects exploitable machine account quota
type MachineAccountQuotaAbuseDetector struct {
	audit.BaseDetector
}

// NewMachineAccountQuotaAbuseDetector creates a new detector
func NewMachineAccountQuotaAbuseDetector() *MachineAccountQuotaAbuseDetector {
	return &MachineAccountQuotaAbuseDetector{
		BaseDetector: audit.NewBaseDetector("MACHINE_ACCOUNT_QUOTA_ABUSE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *MachineAccountQuotaAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return []types.Finding{{
			Type:        d.ID(),
			Severity:    types.SeverityMedium,
			Category:    string(d.Category()),
			Title:       "Machine Account Quota Abuse",
			Description: "Unable to check machine account quota.",
			Count:       0,
		}}
	}

	quota := data.DomainInfo.MachineAccountQuota
	isVulnerable := quota > 0

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Machine Account Quota Abuse",
		Description: "ms-DS-MachineAccountQuota > 0. Non-admin users can join computers to domain (potential Kerberos attacks).",
		Count:       0,
	}

	if isVulnerable {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{types.DomainInfoToAffectedEntity(data.DomainInfo)}
			finding.Details = map[string]interface{}{
				"quota": quota,
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMachineAccountQuotaAbuseDetector())
}
