package gpo

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// FolderOptionsScriptExecDetector detects GPOs that lower file association risk,
// allowing dangerous script types (.hta, .js, .vbs, .wsf) to execute without warning.
type FolderOptionsScriptExecDetector struct {
	audit.BaseDetector
}

func NewFolderOptionsScriptExecDetector() *FolderOptionsScriptExecDetector {
	return &FolderOptionsScriptExecDetector{
		BaseDetector: audit.NewBaseDetector("GPO_FOLDER_OPTIONS_SCRIPT_EXEC", audit.CategoryGPO),
	}
}

// dangerousExtensions are script file types that should not be treated as low-risk
var dangerousExtensions = []string{".hta", ".js", ".vbs", ".wsf", ".wsh", ".ps1"}

func (d *FolderOptionsScriptExecDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Folder Options Allow Script Execution Without Warning",
		Description: "A Group Policy configures file associations to treat dangerous script types (.hta, .js, .vbs, .wsf) as low-risk, allowing them to execute without security warnings. This can be abused for phishing and malware delivery.",
		Count:       0,
	}

	var reasons []string

	// Check DefaultFileTypeRisk = 6152 (treat all as low risk)
	risk := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.FolderOptionsDefaultFileTypeRisk
	})
	if risk != nil && *risk == 6152 {
		reasons = append(reasons, "DefaultFileTypeRisk is set to 6152 (low risk for all file types)")
	}

	// Check LowRiskFileTypes contains dangerous extensions
	lowRisk := helpers.FindRegistrySettingString(data.GPOPolicies, func(rs *audit.RegistrySettings) *string {
		return rs.FolderOptionsLowRiskFileTypes
	})
	if lowRisk != nil {
		lowRiskLower := strings.ToLower(*lowRisk)
		var found []string
		for _, ext := range dangerousExtensions {
			if strings.Contains(lowRiskLower, ext) {
				found = append(found, ext)
			}
		}
		if len(found) > 0 {
			reasons = append(reasons, "LowRiskFileTypes includes dangerous extensions: "+strings.Join(found, ", "))
		}
	}

	if len(reasons) > 0 {
		finding.Count = len(reasons)
		finding.Details = map[string]interface{}{
			"reasons":        reasons,
			"recommendation": "Remove dangerous script extensions from LowRiskFileTypes and do not set DefaultFileTypeRisk to 6152.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewFolderOptionsScriptExecDetector())
}
