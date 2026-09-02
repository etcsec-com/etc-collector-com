package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// FolderOptionsNotHardenedDetector fires when NO GPO configures folder-options
// registry keys that restrict dangerous script extensions (.hta, .js, .vbs, .wsf).
// By default Windows allows double-click execution of these extensions without
// warning — a common phishing/malware delivery vector.
// Complements GPO_FOLDER_OPTIONS_SCRIPT_EXEC (which detects explicit weakening).
// Matches PingCastle S-FolderOptions.
type FolderOptionsNotHardenedDetector struct {
	audit.BaseDetector
}

func NewFolderOptionsNotHardenedDetector() *FolderOptionsNotHardenedDetector {
	return &FolderOptionsNotHardenedDetector{
		BaseDetector: audit.NewBaseDetector("FOLDER_OPTIONS_SCRIPT_NOT_HARDENED", audit.CategoryGPO),
	}
}

func (d *FolderOptionsNotHardenedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Check if ANY GPO sets either of the two folder-options hardening keys.
	hasRiskSetting := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.FolderOptionsDefaultFileTypeRisk
	})
	hasLowRiskSetting := helpers.FindRegistrySettingString(data.GPOPolicies, func(rs *audit.RegistrySettings) *string {
		return rs.FolderOptionsLowRiskFileTypes
	})

	count := 0
	if hasRiskSetting == nil && hasLowRiskSetting == nil {
		count = 1
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "No GPO Hardens Folder-Options Script Execution",
		Description: "No Group Policy configures DefaultFileTypeRisk or LowRiskFileTypes to restrict " +
			"dangerous script extensions (.hta, .js, .vbs, .wsf). By default Windows allows these " +
			"file types to execute on double-click without a security warning, which is a common " +
			"phishing and malware delivery vector.",
		Count: count,
	}

	if count > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Deploy a GPO that sets DefaultFileTypeRisk and removes dangerous extensions from LowRiskFileTypes.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewFolderOptionsNotHardenedDetector())
}
