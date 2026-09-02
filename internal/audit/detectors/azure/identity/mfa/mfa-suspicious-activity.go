package mfa

import (
	"context"
	"fmt"
	"sort"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// MFASuspiciousActivityDetector aggregates Identity Protection signals per user
// to surface suspicious MFA / sign-in activity patterns. It uses existing
// AzureRiskyUsers and AzureRiskySignIns (no new Graph call required, the raw
// /auditLogs/signIns endpoint is intentionally not integrated in this pass to
// stay within existing Graph quota).
//
// Partially matches Purple Knight SI000093.
type MFASuspiciousActivityDetector struct {
	audit.BaseDetector
}

func NewMFASuspiciousActivityDetector() *MFASuspiciousActivityDetector {
	return &MFASuspiciousActivityDetector{
		BaseDetector: audit.NewBaseDetector("MFA_SUSPICIOUS_ACTIVITY", audit.CategoryIdentity),
	}
}

// Thresholds applied to aggregated Identity Protection signals.
const (
	suspiciousMultiIPThreshold    = 3 // distinct IPs in risky sign-ins per user
	suspiciousMultiLocationsLimit = 2 // distinct countries in risky sign-ins per user
	suspiciousHighRiskLimit       = 2 // number of high-risk events
)

func (d *MFASuspiciousActivityDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	type userStats struct {
		ips         map[string]bool
		locations   map[string]bool
		highRisk    int
		anyRiskUser bool
	}
	stats := make(map[string]*userStats)

	// Index risky users first — their presence alone is a signal.
	for _, ru := range data.AzureRiskyUsers {
		if ru.RiskState == "dismissed" || ru.RiskState == "remediated" {
			continue
		}
		if _, ok := stats[ru.UserPrincipalName]; !ok {
			stats[ru.UserPrincipalName] = &userStats{ips: map[string]bool{}, locations: map[string]bool{}}
		}
		stats[ru.UserPrincipalName].anyRiskUser = true
	}

	for _, rs := range data.AzureRiskySignIns {
		if rs.RiskState == "dismissed" || rs.RiskState == "remediated" {
			continue
		}
		s, ok := stats[rs.UserPrincipalName]
		if !ok {
			s = &userStats{ips: map[string]bool{}, locations: map[string]bool{}}
			stats[rs.UserPrincipalName] = s
		}
		if rs.IPAddress != "" {
			s.ips[rs.IPAddress] = true
		}
		if rs.Location != "" {
			s.locations[rs.Location] = true
		}
		if rs.RiskLevel == "high" {
			s.highRisk++
		}
	}

	// Sorted by UPN (T_046/B_048): stats is a map, so ranging it directly
	// gives a randomized order per process — same input, different JSON,
	// different sha256 across runs.
	upns := make([]string, 0, len(stats))
	for upn := range stats {
		upns = append(upns, upn)
	}
	sort.Strings(upns)

	pairs := make([]string, 0)
	anomalousUsers := 0
	for _, upn := range upns {
		s := stats[upn]
		reasons := []string{}
		if len(s.ips) >= suspiciousMultiIPThreshold {
			reasons = append(reasons, fmt.Sprintf("%d distinct IPs", len(s.ips)))
		}
		if len(s.locations) >= suspiciousMultiLocationsLimit {
			reasons = append(reasons, fmt.Sprintf("%d distinct geos", len(s.locations)))
		}
		if s.highRisk >= suspiciousHighRiskLimit {
			reasons = append(reasons, fmt.Sprintf("%d high-risk events", s.highRisk))
		}
		if len(reasons) == 0 {
			continue
		}
		anomalousUsers++
		pairs = append(pairs, fmt.Sprintf("user=%s signals=%v", upn, reasons))
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityHigh,
		Category: string(d.Category()),
		Title:    "Suspicious MFA / sign-in activity pattern",
		Description: "Multiple Identity Protection signals (distinct source IPs, geographies, " +
			"and/or high-risk events) correlate on the same user. This pattern is consistent " +
			"with credential misuse or an in-progress MFA bypass attempt.",
		Count: anomalousUsers,
		Details: map[string]interface{}{
			"recommendation": "Investigate the listed users in Identity Protection. Require a password reset and revoke active sessions if compromise is confirmed.",
			"pairs":          pairs,
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMFASuspiciousActivityDetector())
}
