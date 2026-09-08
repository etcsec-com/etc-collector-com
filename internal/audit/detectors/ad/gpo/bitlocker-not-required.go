package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// BitLockerDetector checks if BitLocker is required via GPO
type BitLockerDetector struct {
	audit.BaseDetector
}

func NewBitLockerDetector() *BitLockerDetector {
	return &BitLockerDetector{
		BaseDetector: audit.NewBaseDetector("BITLOCKER_NOT_REQUIRED", audit.CategoryGPO),
	}
}

func (d *BitLockerDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "BitLocker Not Required via GPO",
		Description: "BitLocker drive encryption is not enforced via Group Policy. Without disk encryption, stolen or decommissioned hardware exposes Active Directory data, cached credentials, and other sensitive information.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.BitLockerRequired
	})

	if v == nil || *v != 1 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Enable BitLocker requirements via GPO and configure recovery key backup to Active Directory.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewBitLockerDetector())
}
