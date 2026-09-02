package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SysvolNetlogonDetector checks for SYSVOL/NETLOGON permission issues
type SysvolNetlogonDetector struct {
	audit.BaseDetector
}

// NewSysvolNetlogonDetector creates a new detector
func NewSysvolNetlogonDetector() *SysvolNetlogonDetector {
	return &SysvolNetlogonDetector{
		BaseDetector: audit.NewBaseDetector("SYSVOL_NETLOGON_PERMISSIONS", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *SysvolNetlogonDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This would require reading SYSVOL share permissions via SMB
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "SYSVOL/NETLOGON Permissions Review",
		Description: "SYSVOL and NETLOGON share permissions should be audited. Weak permissions allow attackers to modify logon scripts and GPOs.",
		Count:       0, // Will be populated when SMB permission reading is implemented
		Details: map[string]interface{}{
			"recommendation": "Review SYSVOL and NETLOGON share permissions. Only Domain Admins should have write access.",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSysvolNetlogonDetector())
}
