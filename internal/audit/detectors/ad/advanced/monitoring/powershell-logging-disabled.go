package monitoring

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PowershellLoggingDisabledDetector detects if PowerShell logging is disabled
type PowershellLoggingDisabledDetector struct {
	audit.BaseDetector
}

// NewPowershellLoggingDisabledDetector creates a new detector
func NewPowershellLoggingDisabledDetector() *PowershellLoggingDisabledDetector {
	return &PowershellLoggingDisabledDetector{
		BaseDetector: audit.NewBaseDetector("POWERSHELL_LOGGING_DISABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *PowershellLoggingDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "PowerShell Logging Disabled",
		Description: "PowerShell Script Block Logging is not enabled, preventing detection of malicious PowerShell activity.",
		Count:       0,
	}

	scriptBlockLogging := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.PSScriptBlockLogging
	})
	moduleLogging := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.PSModuleLogging
	})

	var disabled []string
	if scriptBlockLogging != nil && *scriptBlockLogging != 1 {
		disabled = append(disabled, "ScriptBlockLogging")
	} else if scriptBlockLogging == nil {
		// Not configured = disabled by default
		if data.GPOPolicies != nil && len(data.GPOPolicies) > 0 {
			disabled = append(disabled, "ScriptBlockLogging")
		}
	}

	if moduleLogging != nil && *moduleLogging != 1 {
		disabled = append(disabled, "ModuleLogging")
	} else if moduleLogging == nil {
		if data.GPOPolicies != nil && len(data.GPOPolicies) > 0 {
			disabled = append(disabled, "ModuleLogging")
		}
	}

	if len(disabled) > 0 {
		finding.Count = len(disabled)
		finding.Details = map[string]interface{}{
			"disabledFeatures": disabled,
			"recommendation":   "Enable 'Turn on PowerShell Script Block Logging' and 'Turn on Module Logging' via Group Policy.",
		}
		if data.IncludeDetails {
			entities := make([]types.AffectedEntity, len(disabled))
			for i, feat := range disabled {
				entities[i] = types.AffectedEntity{Type: "config", Name: feat}
			}
			finding.AffectedEntities = entities
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPowershellLoggingDisabledDetector())
}
