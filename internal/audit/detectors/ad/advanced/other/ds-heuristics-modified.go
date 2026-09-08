package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DsHeuristicsModifiedDetector detects modified dsHeuristics attribute
type DsHeuristicsModifiedDetector struct {
	audit.BaseDetector
}

// NewDsHeuristicsModifiedDetector creates a new detector
func NewDsHeuristicsModifiedDetector() *DsHeuristicsModifiedDetector {
	return &DsHeuristicsModifiedDetector{
		BaseDetector: audit.NewBaseDetector("DS_HEURISTICS_MODIFIED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *DsHeuristicsModifiedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return []types.Finding{{
			Type:        d.ID(),
			Severity:    types.SeverityMedium,
			Category:    string(d.Category()),
			Title:       "dsHeuristics Status Unknown",
			Description: "Unable to check dsHeuristics attribute.",
			Count:       0,
		}}
	}

	dsHeuristics := data.DomainInfo.DsHeuristics
	isModified := dsHeuristics != ""

	// Check for specific dangerous settings
	var dangerousSettings []string
	// Position 6 (0-indexed) = 7th character = fLDAPBlockAnonOps. [MS-ADTS]:
	// dSHeuristics character table, row 7: "If this character is '2', then
	// the fLDAPBlockAnonOps heuristic is FALSE" (anonymous LDAP operations
	// are NOT blocked, i.e. allowed).
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5
	if len(dsHeuristics) >= 7 && dsHeuristics[6] == '2' {
		dangerousSettings = append(dangerousSettings, "Anonymous LDAP operations allowed (position 7)")
	}

	// Settings that change AD's default behavior but are hardening
	// features, not weaknesses - tracked separately from dangerousSettings
	// so a hardening change is never reported as if it were a vulnerability.
	var hardeningSettings []string
	// Position 2 (0-indexed) = 3rd character = fDoListObject. [MS-ADTS]:
	// dSHeuristics character table, row 3: "If this character is '1', then
	// the fDoListObject heuristic is TRUE; otherwise, ... FALSE" (default is
	// FALSE/"0"). List Object mode TRUE restricts visibility of child
	// objects to principals holding explicit list rights - a hardening of
	// object enumeration, not a weakening. The previous label here ("List
	// Object mode disabled") had the value inverted: '1' means the mode is
	// ENABLED.
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5
	if len(dsHeuristics) >= 3 && dsHeuristics[2] == '1' {
		hardeningSettings = append(hardeningSettings, "List Object mode enabled (position 3) - restricts object visibility to explicit list rights; confirm this is an intentional change")
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "dsHeuristics Modified",
		Description: "The dsHeuristics attribute has been modified from defaults. This may weaken AD security or enable dangerous features.",
		Count:       0,
	}

	if isModified {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"currentValue":   dsHeuristics,
			"recommendation": "Review dsHeuristics value and document any intentional modifications.",
		}
		if len(dangerousSettings) > 0 {
			finding.Details["dangerousSettings"] = dangerousSettings
		}
		if len(hardeningSettings) > 0 {
			finding.Details["hardeningSettings"] = hardeningSettings
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDsHeuristicsModifiedDetector())
}
