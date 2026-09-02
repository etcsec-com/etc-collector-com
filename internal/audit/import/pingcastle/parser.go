// Package pingcastle parses a PingCastle ad_hc_*.xml report and converts it
// into the collector's native types.AuditResult so the GUI can render an
// imported report in the same audit-view as a native AD audit.
//
// PingCastle's score scale is inverted vs ours: higher GlobalScore = more
// risky. We map score = max(0, 100 - GlobalScore) so the GUI's existing
// CalculateRating produces a consistent rating.
package pingcastle

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// HealthcheckData is the root of a PingCastle XML report.
type HealthcheckData struct {
	XMLName               xml.Name              `xml:"HealthcheckData"`
	ApproximateUserCount  int                   `xml:"ApproximateUserCount,attr"`
	EngineVersion         string                `xml:"EngineVersion"`
	GenerationDate        string                `xml:"GenerationDate"`
	DomainFQDN            string                `xml:"DomainFQDN"`
	NetBIOSName           string                `xml:"NetBIOSName"`
	ForestFQDN            string                `xml:"ForestFQDN"`
	DomainSid             string                `xml:"DomainSid"`
	NumberOfDC            int                   `xml:"NumberOfDC"`
	GlobalScore           int                   `xml:"GlobalScore"`
	StaleObjectsScore     int                   `xml:"StaleObjectsScore"`
	PrivilegiedGroupScore int                   `xml:"PrivilegiedGroupScore"`
	TrustScore            int                   `xml:"TrustScore"`
	AnomalyScore          int                   `xml:"AnomalyScore"`
	DomainControllers     []DomainController    `xml:"DomainControllers>HealthcheckDomainController"`
	RiskRules             []HealthcheckRiskRule `xml:"RiskRules>HealthcheckRiskRule"`
}

// DomainController mirrors PingCastle's HealthcheckDomainController.
type DomainController struct {
	DCName                 string `xml:"DCName"`
	DistinguishedName      string `xml:"DistinguishedName"`
	OperatingSystem        string `xml:"OperatingSystem"`
	OperatingSystemVersion string `xml:"OperatingSystemVersion"`
	IsGlobalCatalog        bool   `xml:"IsGlobalCatalog"`
	IsReadOnly             bool   `xml:"IsReadOnly"`
}

// HealthcheckRiskRule is one entry in PingCastle's <RiskRules>.
type HealthcheckRiskRule struct {
	Points    int    `xml:"Points"`
	Category  string `xml:"Category"`
	Model     string `xml:"Model"`
	RiskID    string `xml:"RiskId"`
	Rationale string `xml:"Rationale"`
}

// Parse decodes a PingCastle XML payload into types.AuditResult.
//
// Severity from Points (PingCastle convention):
//   - >= 50: critical
//   - 20-49: high
//   - 10-19: medium
//   - 1-9 : low
//   - 0  : info
//
// Category labels are normalised to the snake_case scheme the audit-view
// already understands (privileged_accounts / stale_objects / anomalies /
// trusts).
func Parse(xmlBytes []byte) (*types.AuditResult, error) {
	var hc HealthcheckData
	if err := xml.Unmarshal(xmlBytes, &hc); err != nil {
		return nil, fmt.Errorf("parse pingcastle xml: %w", err)
	}

	stats := types.NewAuditStatistics()
	findings := make([]types.Finding, 0, len(hc.RiskRules))
	for _, r := range hc.RiskRules {
		sev := pointsToSeverity(r.Points)
		cat := mapCategory(r.Category, r.RiskID)
		findings = append(findings, types.Finding{
			Type:        r.RiskID,
			Severity:    sev,
			Category:    cat,
			Title:       r.RiskID,
			Description: strings.TrimSpace(r.Rationale),
			Count:       1,
			Details: map[string]interface{}{
				"pingcastle_points":   r.Points,
				"pingcastle_model":    r.Model,
				"pingcastle_category": r.Category,
				"source":              "pingcastle-import",
			},
		})
		stats.BySeverity[sev]++
		stats.ByCategory[cat]++
		stats.TotalFindings++
	}

	stats.UsersScanned = hc.ApproximateUserCount
	stats.ComputersScanned = len(hc.DomainControllers)

	score := float64(100 - hc.GlobalScore)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	ts, err := time.Parse(time.RFC3339Nano, hc.GenerationDate)
	if err != nil {
		ts = time.Now()
	}

	domain := hc.DomainFQDN
	if domain == "" {
		domain = hc.NetBIOSName
	}

	return &types.AuditResult{
		Timestamp:  ts,
		Provider:   "ad-pingcastle-import",
		Domain:     domain,
		Score:      score,
		Rating:     types.CalculateRating(score),
		Findings:   findings,
		Statistics: stats,
	}, nil
}

func pointsToSeverity(points int) types.Severity {
	switch {
	case points >= 50:
		return types.SeverityCritical
	case points >= 20:
		return types.SeverityHigh
	case points >= 10:
		return types.SeverityMedium
	case points >= 1:
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

// mapCategory routes a PingCastle Category + RiskID into the canonical
// collector category names that types.ConvertToTSFormat understands.
// Unknown buckets land in extendedConfig (the GUI's "Findings" tab still
// renders them, but they're not grouped under any nice section).
func mapCategory(category, riskID string) string {
	switch category {
	case "PrivilegedAccounts":
		return "accounts"
	case "StaleObjects":
		// Obsolete OS / DC issues belong in computers; everything else
		// (stale users, password age, etc.) is an account hygiene issue.
		switch {
		case strings.HasPrefix(riskID, "S-OS-"),
			strings.HasPrefix(riskID, "S-DC-"):
			return "computers"
		default:
			return "accounts"
		}
	case "Anomalies":
		return "advanced"
	case "Trusts":
		return "trusts"
	default:
		return strings.ToLower(category)
	}
}
