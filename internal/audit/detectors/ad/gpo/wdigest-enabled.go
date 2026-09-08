package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WDigestDetector checks if WDigest authentication stores cleartext credentials in memory
type WDigestDetector struct {
	audit.BaseDetector
}

func NewWDigestDetector() *WDigestDetector {
	return &WDigestDetector{
		BaseDetector: audit.NewBaseDetector("WDIGEST_ENABLED", audit.CategoryGPO),
	}
}

func (d *WDigestDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "WDigest Authentication Stores Cleartext Credentials",
		Description: "WDigest UseLogonCredential is not explicitly disabled. On systems prior to Windows 8.1/2012 R2, or when enabled, WDigest stores cleartext passwords in LSASS memory, which can be extracted with tools like Mimikatz.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.WDigestUseLogonCredential
	})

	// If not configured (nil) or set to 1 (enabled), it's a risk
	if v == nil || *v != 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential to 0 via GPO.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWDigestDetector())
}
