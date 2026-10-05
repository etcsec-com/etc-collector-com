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

// dfsrAvailableLevel is the domain functional level (Windows Server 2008,
// see domainLevelNames above) from which DFSR has been available for SYSVOL
// replication, per Microsoft's migration guide (cited below). Below this
// level a domain has no way to migrate off FRS yet, so staying on FRS isn't
// an actionable finding there.
const dfsrAvailableLevel = 3

// dfsrMigrationDoc is Microsoft's own migration guide, which documents both
// the Windows Server 2008 functional-level requirement for DFSR and FRS's
// deprecation (FRS was deprecated in Windows Server 2008 R2, per
// https://learn.microsoft.com/en-us/windows/win32/win7appqual/file-replication-service--frs--is-deprecated-in-windows-server-2008-r2).
const dfsrMigrationDoc = "https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr"

// Detect executes the detection
func (d *DfsrDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	domainLevel := 0
	usingFRS := false
	if data.DomainInfo != nil {
		domainLevel = data.DomainInfo.FunctionalLevelInt
		usingFRS = data.DomainInfo.UsingNTFRSForSYSVOL
	}

	// Only flag a domain that (a) is confirmed still using FRS for SYSVOL
	// (LDAP nTFRSSubscriber evidence, not a guess) AND (b) is already at a
	// functional level where DFSR migration is possible. A domain below
	// dfsrAvailableLevel can't migrate yet regardless of FRS use, so it's
	// not flagged here - that gap belongs to the functional-level checks.
	staleOnFRS := usingFRS && domainLevel >= dfsrAvailableLevel

	count := 0
	if staleOnFRS {
		count = 1
	}

	recommendation := "Verify DFSR health with dcdiag /e /test:dfsrevent"
	if staleOnFRS {
		recommendation = "Migrate SYSVOL replication from FRS to DFSR using dfsrmig.exe"
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "DFSR Migration Status",
		Description: "FRS (File Replication Service) was deprecated in Windows Server 2008 R2; DFSR (DFS Replication) has been available for SYSVOL since the Windows Server 2008 domain functional level. This flags domains confirmed still using FRS for SYSVOL despite a functional level that already supports migrating to DFSR. Source: https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr",
		Count:       count,
		Details: map[string]interface{}{
			"domainFunctionalLevel":     domainLevel,
			"domainFunctionalLevelName": getDomainLevelName(domainLevel),
			"usingNTFRSForSYSVOL":       usingFRS,
			"recommendation":            recommendation,
			"microsoftDoc":              dfsrMigrationDoc,
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDfsrDetector())
}
