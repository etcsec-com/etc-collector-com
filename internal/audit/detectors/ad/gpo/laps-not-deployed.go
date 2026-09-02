package gpo

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LAPSNotDeployedDetector checks if LAPS is deployed via GPO
type LAPSNotDeployedDetector struct {
	audit.BaseDetector
}

// NewLAPSNotDeployedDetector creates a new detector
func NewLAPSNotDeployedDetector() *LAPSNotDeployedDetector {
	return &LAPSNotDeployedDetector{
		BaseDetector: audit.NewBaseDetector("GPO_LAPS_NOT_DEPLOYED", audit.CategoryGPO),
	}
}

// LAPS CSE GUIDs
var lapsCseGuids = []string{
	"{D76B9641-3288-4f75-942D-087DE603E3EA}", // Legacy LAPS
	"{4BCD6CDE-777B-48B6-9804-43568E23545D}", // Windows LAPS
}

func hasLAPSCse(gpo types.GPO) bool {
	for _, cse := range gpo.CSEGuids {
		cseUpper := strings.ToUpper(cse)
		for _, guid := range lapsCseGuids {
			if strings.Contains(cseUpper, strings.ToUpper(guid)) {
				return true
			}
		}
	}
	return false
}

// Detect executes the detection
func (d *LAPSNotDeployedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Check if any GPO has LAPS CSE and is linked
	var lapsGpos []types.GPO
	for _, gpo := range data.GPOs {
		if hasLAPSCse(gpo) {
			lapsGpos = append(lapsGpos, gpo)
		}
	}

	// Check if any LAPS GPO is linked
	linkedLapsCount := 0
	for _, gpo := range lapsGpos {
		for _, link := range data.GPOLinks {
			if strings.EqualFold(link.GPOCN, gpo.CN) && link.LinkEnabled {
				linkedLapsCount++
				break
			}
		}
	}

	noLapsDeployed := linkedLapsCount == 0

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "LAPS Not Deployed via GPO",
		Description: "No active Group Policy Object was found deploying LAPS (Local Administrator Password Solution). This leaves local admin passwords vulnerable to reuse attacks.",
		Count:       0,
		Details: map[string]interface{}{
			"lapsGposFound":  len(lapsGpos),
			"linkedLapsGpos": linkedLapsCount,
		},
	}

	if noLapsDeployed {
		finding.Count = 1
		finding.Details["note"] = "LAPS not deployed - local admin passwords are not being rotated."
		finding.Details["recommendation"] = "Deploy LAPS via GPO to manage local administrator passwords."
	} else {
		finding.Details["note"] = "LAPS is deployed via GPO."
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLAPSNotDeployedDetector())
}
