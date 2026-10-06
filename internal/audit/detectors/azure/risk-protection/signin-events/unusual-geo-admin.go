package signinevents

import (
	"context"
	"fmt"
	"sort"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ===== RISK_UNUSUAL_GEO_ADMIN =====

type UnusualGeoAdminDetector struct {
	audit.BaseDetector
}

func NewUnusualGeoAdminDetector() *UnusualGeoAdminDetector {
	return &UnusualGeoAdminDetector{BaseDetector: audit.NewBaseDetector(RISK_UNUSUAL_GEO_ADMIN, audit.CategoryRiskProtection)}
}

func (d *UnusualGeoAdminDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Admin Sign-In From Unusual Country",
		Description: "A privileged account signed in successfully from a country it had not used earlier in the collected window. A new geography on an admin account is a common first sign of credential or token theft.",
		Count:       0,
	}
	if data == nil || len(data.AzureSignInLogs) == 0 {
		return []types.Finding{finding}
	}
	if data.AzureSignInLogsTruncated {
		return []types.Finding{incompleteStreamFinding(d.ID(), string(d.Category()), finding.Title, data)}
	}
	// Without role assignments we cannot tell an admin from anyone else.
	// Reporting every user's travel would be noise, and reporting nothing
	// without saying why would be worse - so the guard is explicit.
	admins := buildAdminUserSet(data.AzureRoleAssignments)
	if len(admins) == 0 {
		return []types.Finding{finding}
	}

	// Successful sign-ins only, on both sides of the split: a failed attempt
	// from a new country is a different signal (covered by the burst
	// detectors) and would inflate this one.
	adminEvents := make([]types.SignInLog, 0, len(data.AzureSignInLogs))
	for i := range data.AzureSignInLogs {
		ev := &data.AzureSignInLogs[i]
		if !signInSuccess(ev) {
			continue
		}
		key := userKey(ev)
		if key == "" || !admins[key] {
			continue
		}
		adminEvents = append(adminEvents, *ev)
	}
	oldest, newest, ok := windowBounds(adminEvents)
	if !ok {
		return []types.Finding{finding}
	}
	recentStart := newest.Add(-baselineRecentWindow)
	baselineDays := recentStart.Sub(oldest).Hours() / 24
	if baselineDays < baselineMinDays {
		return []types.Finding{finding}
	}

	type adminGeo struct {
		known         map[string]bool
		baselineCount int
		newCountries  map[string]*types.SignInLog
		display       *types.SignInLog
	}
	byAdmin := map[string]*adminGeo{}

	for i := range adminEvents {
		ev := &adminEvents[i]
		key := userKey(ev)
		acc := byAdmin[key]
		if acc == nil {
			acc = &adminGeo{known: map[string]bool{}, newCountries: map[string]*types.SignInLog{}}
			byAdmin[key] = acc
		}
		if acc.display == nil {
			acc.display = ev
		}
		country := normalizeCountry(locationCountry(ev))
		if ev.CreatedDateTime.Before(recentStart) {
			acc.baselineCount++
			// An event with no resolved country tells us nothing about where
			// this admin usually signs in - it must not narrow the known set.
			if country != "" {
				acc.known[country] = true
			}
			continue
		}
		if country == "" {
			continue
		}
		if _, seen := acc.newCountries[country]; !seen {
			acc.newCountries[country] = ev
		}
	}

	var affected []types.AffectedEntity
	for _, acc := range byAdmin {
		// No established pattern → no "unusual". A newly created admin, or one
		// whose baseline sign-ins carry no geolocation, must not be reported
		// simply because we have nothing to compare against.
		if acc.baselineCount < geoMinBaselineSignIns || len(acc.known) == 0 {
			continue
		}
		var unseen []string
		for country := range acc.newCountries {
			if !acc.known[country] {
				unseen = append(unseen, country)
			}
		}
		if len(unseen) == 0 {
			continue
		}
		sort.Strings(unseen)
		if data.IncludeDetails {
			ev := acc.newCountries[unseen[0]]
			if ev == nil {
				ev = acc.display
			}
			affected = append(affected, newUserRiskEntity(ev, map[string]any{
				"newCountries":     unseen,
				"knownCountries":   sortedKeys(acc.known),
				"baselineSignIns":  acc.baselineCount,
				"baselineDays":     round1(baselineDays),
				"firstSeenAt":      formatTime(ev.CreatedDateTime),
				"sourceIp":         ev.IPAddress,
				"location":         locationLabel(ev.Location),
				"windowStart":      formatTime(oldest),
				"recentWindowFrom": formatTime(recentStart),
			}))
		}
		finding.Count++
	}
	sortAffectedUsers(affected)
	finding.AffectedEntities = affected
	if finding.Count == 1 && len(affected) == 1 {
		c := affected[0].Azure.SignInRiskContext
		who := affected[0].UserPrincipalName
		if who == "" {
			who = affected[0].DN
		}
		finding.Description = fmt.Sprintf(
			"Privileged account %s signed in from %v, not seen for that account over the preceding %v days of the collected window (Graph retains 30 days at most, so the history spans days, not months).",
			who, c["newCountries"], c["baselineDays"],
		)
	}
	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUnusualGeoAdminDetector())
}

// sortedKeys returns the map keys sorted, for deterministic evidence.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
