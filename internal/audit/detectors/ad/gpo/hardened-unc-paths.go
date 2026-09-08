package gpo

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// HardenedUNCPathsDetector checks if hardened UNC paths are configured for SYSVOL and NETLOGON
type HardenedUNCPathsDetector struct {
	audit.BaseDetector
}

func NewHardenedUNCPathsDetector() *HardenedUNCPathsDetector {
	return &HardenedUNCPathsDetector{
		BaseDetector: audit.NewBaseDetector("HARDENED_UNC_PATHS_WEAK", audit.CategoryGPO),
	}
}

func (d *HardenedUNCPathsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Hardened UNC Paths Not Configured",
		Description: "Hardened UNC paths are not properly configured for SYSVOL and NETLOGON shares. Without RequireMutualAuthentication and RequireIntegrity, GPO settings can be tampered with during transit, enabling attacks like GPO hijacking.",
		Count:       0,
	}

	issues := []string{}

	netlogon := helpers.FindRegistrySettingString(data.GPOPolicies, func(rs *audit.RegistrySettings) *string {
		return rs.HardenedPathsNetlogon
	})
	if netlogon == nil || !isHardenedPath(*netlogon) {
		issues = append(issues, "NETLOGON hardened path not configured or missing RequireMutualAuthentication/RequireIntegrity")
	}

	sysvol := helpers.FindRegistrySettingString(data.GPOPolicies, func(rs *audit.RegistrySettings) *string {
		return rs.HardenedPathsSysvol
	})
	if sysvol == nil || !isHardenedPath(*sysvol) {
		issues = append(issues, "SYSVOL hardened path not configured or missing RequireMutualAuthentication/RequireIntegrity")
	}

	finding.Count = len(issues)
	if len(issues) > 0 {
		finding.Details = map[string]interface{}{
			"issues":         issues,
			"recommendation": "Configure hardened UNC paths with RequireMutualAuthentication=1,RequireIntegrity=1 for \\\\*\\NETLOGON and \\\\*\\SYSVOL.",
		}
		if data.IncludeDetails {
			entities := make([]types.AffectedEntity, len(issues))
			for i, issue := range issues {
				entities[i] = types.AffectedEntity{Type: "config", Name: issue}
			}
			finding.AffectedEntities = entities
		}
	}

	return []types.Finding{finding}
}

// isHardenedPath checks if a UNC path setting has required security attributes
func isHardenedPath(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "requiremutualauthentication=1") && strings.Contains(lower, "requireintegrity=1")
}

func init() {
	audit.MustRegister(NewHardenedUNCPathsDetector())
}
