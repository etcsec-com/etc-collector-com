package signing

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SmbV1EnabledDetector detects if SMBv1 is enabled
type SmbV1EnabledDetector struct {
	audit.BaseDetector
}

// NewSmbV1EnabledDetector creates a new detector
func NewSmbV1EnabledDetector() *SmbV1EnabledDetector {
	return &SmbV1EnabledDetector{
		BaseDetector: audit.NewBaseDetector("SMB_V1_ENABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *SmbV1EnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "SMBv1 Enabled",
		Description: "SMBv1 is enabled on domain controllers. SMBv1 is deprecated and vulnerable to critical attacks (EternalBlue, WannaCry).",
		Count:       0,
	}

	smb1 := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.SMB1Enabled
	})

	if smb1 != nil && *smb1 != 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"currentValue":   *smb1,
			"recommendation": "Disable SMBv1 via Group Policy or Windows Features. Use SMBv2/v3 instead.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSmbV1EnabledDetector())
}
