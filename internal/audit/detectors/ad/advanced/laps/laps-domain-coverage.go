package laps

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LAPSDomainCoverageDetector detects insufficient LAPS coverage across the domain
type LAPSDomainCoverageDetector struct {
	audit.BaseDetector
}

// NewLAPSDomainCoverageDetector creates a new detector
func NewLAPSDomainCoverageDetector() *LAPSDomainCoverageDetector {
	return &LAPSDomainCoverageDetector{
		BaseDetector: audit.NewBaseDetector("LAPS_DOMAIN_COVERAGE_LOW", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *LAPSDomainCoverageDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const serverTrustAccount = 0x2000 // DC flag

	var (
		workstationsTotal, workstationsWithLAPS int
		serversTotal, serversWithLAPS           int
		uncoveredWorkstations, uncoveredServers []types.Computer
	)

	for _, c := range data.Computers {
		if c.Disabled || (c.UserAccountControl&serverTrustAccount) != 0 {
			continue // Skip disabled and DCs
		}

		hasLAPS := c.HasLegacyLAPS || c.HasWindowsLAPS
		isServer := strings.Contains(strings.ToLower(c.OperatingSystem), "server")

		if isServer {
			serversTotal++
			if hasLAPS {
				serversWithLAPS++
			} else {
				uncoveredServers = append(uncoveredServers, c)
			}
		} else {
			workstationsTotal++
			if hasLAPS {
				workstationsWithLAPS++
			} else {
				uncoveredWorkstations = append(uncoveredWorkstations, c)
			}
		}
	}

	// Calculate coverage
	workstationCoverage := 0.0
	serverCoverage := 0.0

	if workstationsTotal > 0 {
		workstationCoverage = float64(workstationsWithLAPS) / float64(workstationsTotal) * 100
	}
	if serversTotal > 0 {
		serverCoverage = float64(serversWithLAPS) / float64(serversTotal) * 100
	}

	totalComputers := workstationsTotal + serversTotal
	overallCoverage := 0.0
	if totalComputers > 0 {
		overallCoverage = float64(workstationsWithLAPS+serversWithLAPS) / float64(totalComputers) * 100
	}

	// Severity based on thresholds
	severity := types.SeverityInfo
	if overallCoverage < 80 {
		severity = types.SeverityHigh
	} else if overallCoverage < 95 {
		severity = types.SeverityMedium
	}

	// Only create finding if coverage < 95%
	if overallCoverage >= 95 {
		return []types.Finding{}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    severity,
		Category:    string(d.Category()),
		Title:       fmt.Sprintf("LAPS Coverage Low (%.1f%%)", overallCoverage),
		Description: fmt.Sprintf("LAPS deployment coverage is %.1f%% across domain computers. Industry best practice recommends >95%% coverage.", overallCoverage),
		// T_036 — this was len(uncovered), i.e. the same machines
		// COMPUTER_NO_LAPS already lists, with a byte-identical entity set: one
		// gap counted twice. This finding is a DOMAIN-level metric — one domain,
		// one coverage figure. The per-machine list belongs to COMPUTER_NO_LAPS
		// alone (detectors/ad/dedup.go, rule R2); the counts below keep the
		// breakdown that made the list useful here.
		Count: 1,
		Details: map[string]interface{}{
			"overallCoverage":       fmt.Sprintf("%.1f%%", overallCoverage),
			"workstationCoverage":   fmt.Sprintf("%.1f%%", workstationCoverage),
			"serverCoverage":        fmt.Sprintf("%.1f%%", serverCoverage),
			"uncoveredWorkstations": len(uncoveredWorkstations),
			"uncoveredServers":      len(uncoveredServers),
			"scope":                 "domain",
			"perMachineFinding":     "COMPUTER_NO_LAPS",
			"recommendation":        "Deploy LAPS to all workstations and servers; the per-machine list is reported by COMPUTER_NO_LAPS.",
		},
	}

	if data.IncludeDetails && data.DomainInfo != nil && data.DomainInfo.DomainDN != "" {
		finding.AffectedEntities = []types.AffectedEntity{data.EntityForDN(data.DomainInfo.DomainDN)}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLAPSDomainCoverageDetector())
}
