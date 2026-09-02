package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DfsrDetector checks if DFSR is not configured (legacy FRS in use)
type DfsrDetector struct {
	audit.BaseDetector
}

// NewDfsrDetector creates a new detector
func NewDfsrDetector() *DfsrDetector {
	return &DfsrDetector{
		BaseDetector: audit.NewBaseDetector("DFSR_NOT_CONFIGURED", audit.CategoryNetwork),
	}
}

var domainLevelNames = map[int]string{
	0: "Windows 2000",
	1: "Windows Server 2003 Interim",
	2: "Windows Server 2003",
	3: "Windows Server 2008",
	4: "Windows Server 2008 R2",
	5: "Windows Server 2012",
	6: "Windows Server 2012 R2",
	7: "Windows Server 2016",
}

func getDomainLevelName(level int) string {
	if name, ok := domainLevelNames[level]; ok {
		return name
	}
	return "Unknown"
}

// Detect executes the detection
func (d *DfsrDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	domainLevel := 0
	if data.DomainInfo != nil {
		domainLevel = data.DomainInfo.FunctionalLevelInt
	}

	// If level is 2003 or lower, might still be using FRS
	potentialFrsUse := domainLevel <= 2

	count := 0
	if potentialFrsUse {
		count = 1
	}

	recommendation := "Verify DFSR health with dcdiag /e /test:dfsrevent"
	if potentialFrsUse {
		recommendation = "Migrate SYSVOL replication from FRS to DFSR using dfsrmig.exe"
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "DFSR Migration Status",
		Description: "FRS (File Replication Service) is deprecated. SYSVOL should be replicated using DFSR (DFS Replication) for better reliability.",
		Count:       count,
		Details: map[string]interface{}{
			"domainFunctionalLevel":     domainLevel,
			"domainFunctionalLevelName": getDomainLevelName(domainLevel),
			"potentialFrsUse":           potentialFrsUse,
			"recommendation":            recommendation,
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDfsrDetector())
}
