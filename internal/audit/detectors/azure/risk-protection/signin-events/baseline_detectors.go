package signinevents

// Baseline-relative sign-in risk detectors (Phase 3 Gap A).
//
// Both compare a recent slice of the collected sign-in stream against the
// earlier part of that SAME stream.
//
// They cannot use the "30-day baseline" / "90-day country history" the
// original request describes, and the reason is a hard limit rather than a
// shortcut: Microsoft Graph retains /auditLogs/signIns for 30 days at most and
// the engine clamps the lookback to it (engine.go, "retention max = 30 days").
// The whole collected window is therefore ≤ 30 days and there is no prior
// history to compare it against. Cross-run history needs the local persistence
// work, which is a separate ticket — until it lands, an in-window baseline is
// the honest maximum.
//
// The consequence is stated in each finding's description, so a reader knows
// the comparison covers days and not months.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	RISK_SP_SIGNIN_SPIKE   = "RISK_SP_SIGNIN_SPIKE"
	RISK_UNUSUAL_GEO_ADMIN = "RISK_UNUSUAL_GEO_ADMIN"

	// The recent slice under scrutiny: the last day of the collected window.
	// Anchored on the newest collected event rather than time.Now(), so a
	// collection that ran hours ago still compares the right days.
	baselineRecentWindow = 24 * time.Hour

	// Minimum baseline span before a comparison means anything. Below this,
	// "unusual" is indistinguishable from "we only just started looking".
	baselineMinDays = 7

	// Service-principal spike: the recent daily rate must exceed the baseline
	// daily rate by this factor...
	spSpikeRatio = 5.0
	// ...and clear an absolute floor, so 1 sign-in against a baseline of 0.1/day
	// is not reported as a 10× spike.
	spSpikeMinRecentEvents = 20

	// Unusual admin geography: the admin must have this many successful
	// baseline sign-ins before the set of countries counts as "their usual".
	geoMinBaselineSignIns = 5
)

// spSignInEventTypes mirrors the app-only sign-in flows the sign-in log
// aggregation already isolates: only servicePrincipal / managedIdentity flows
// are machine traffic. An interactiveUser sign-in also carries an appId but
// represents a human action, and would drown the per-app rate.
func isServicePrincipalSignIn(ev *types.SignInLog) bool {
	if ev == nil {
		return false
	}
	for _, t := range ev.SignInEventTypes {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "serviceprincipal", "managedidentity":
			return true
		}
	}
	return false
}

// newSPSignInRiskEntity deliberately does NOT use the canonical
// "servicePrincipal" entity type: its marshaller in pkg/types/finding.go does
// not merge SignInRiskContext, so every piece of evidence below (baseline
// rate, recent count, ratio) would be silently dropped from the audit JSON.
// The generic marshaller — the same fallback newIPRiskEntity relies on for
// "ip_address" — does merge it. Fixing the servicePrincipal marshaller means
// touching shared core, which this ticket does not scope; see the delivery.
func newSPSignInRiskEntity(appID, appName string, ctx map[string]any) types.AffectedEntity {
	display := appName
	if display == "" {
		display = appID
	}
	return types.AffectedEntity{
		Type:        "servicePrincipalSignIn",
		DN:          appID,
		Name:        display,
		DisplayName: display,
		Azure: &types.AzureEntityFields{
			SignInRiskContext: ctx,
		},
	}
}

// windowBounds returns the oldest and newest event timestamps in the slice.
func windowBounds(logs []types.SignInLog) (oldest, newest time.Time, ok bool) {
	for i := range logs {
		at := logs[i].CreatedDateTime
		if at.IsZero() {
			continue
		}
		if !ok {
			oldest, newest, ok = at, at, true
			continue
		}
		if at.Before(oldest) {
			oldest = at
		}
		if at.After(newest) {
			newest = at
		}
	}
	return oldest, newest, ok
}

// incompleteStreamFinding reports that a baseline comparison was NOT attempted
// because the sign-in stream is incomplete.
//
// Truncation is not a neutral loss here. Graph returns /auditLogs/signIns
// newest-first and collection stops at the event cap or the time budget, so
// what gets dropped is the OLDEST end — precisely the baseline. Computing a
// ratio against a partially collected baseline inflates it, which would turn a
// collection limit into a stream of false positives.
//
// Emitting nothing would be just as wrong: a clean report would then be
// indistinguishable from an unanalysed one. So the finding is emitted at Info
// severity — visible in the report, zero weight in the score — saying the
// analysis did not run and how to make it run.
func incompleteStreamFinding(id, category, title string, data *audit.DetectorData) types.Finding {
	detail := "the sign-in log stream was truncated during collection"
	if data.AzureSignInLogsEventsCollected > 0 {
		detail = fmt.Sprintf("%s (%d events collected)", detail, data.AzureSignInLogsEventsCollected)
	}
	return types.Finding{
		Type:     id,
		Severity: types.SeverityInfo,
		Category: category,
		Title:    title + " — analysis skipped (incomplete data)",
		Description: fmt.Sprintf(
			"This check was NOT performed: %s. It compares recent activity against the earlier part of the same window, and truncation drops the oldest events first — the baseline. Running it anyway would report spikes that are collection artefacts. Raise --azure-signin-logs-max and --azure-signin-logs-budget, then re-run. This is not a clean result.",
			detail,
		),
		Count: 1,
		Details: map[string]interface{}{
			"analysisSkipped": "signInLogsTruncated",
			"eventsCollected": data.AzureSignInLogsEventsCollected,
			"requestedDays":   data.AzureSignInLogsRequestedDays,
			"actualDays":      data.AzureSignInLogsActualDays,
		},
	}
}

// ===== RISK_SP_SIGNIN_SPIKE =====

type SPSignInSpikeDetector struct {
	audit.BaseDetector
}

func NewSPSignInSpikeDetector() *SPSignInSpikeDetector {
	return &SPSignInSpikeDetector{BaseDetector: audit.NewBaseDetector(RISK_SP_SIGNIN_SPIKE, audit.CategoryRiskProtection)}
}

func (d *SPSignInSpikeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Service Principal Sign-In Spike",
		Description: "A service principal signed in far more often in the last 24 hours than over the preceding days of the collected window. A sudden rate change on a machine identity is a token-abuse or compromised-credential signal.",
		Count:       0,
	}
	if data == nil || len(data.AzureSignInLogs) == 0 {
		return []types.Finding{finding}
	}
	if data.AzureSignInLogsTruncated {
		return []types.Finding{incompleteStreamFinding(d.ID(), string(d.Category()), finding.Title, data)}
	}

	// Machine flows only, keyed by application ID.
	type spEvents struct {
		appName  string
		baseline int
		recent   int
		lastSeen time.Time
	}
	byApp := map[string]*spEvents{}

	spOnly := make([]types.SignInLog, 0, len(data.AzureSignInLogs))
	for i := range data.AzureSignInLogs {
		ev := &data.AzureSignInLogs[i]
		if isServicePrincipalSignIn(ev) && strings.TrimSpace(ev.AppID) != "" {
			spOnly = append(spOnly, *ev)
		}
	}
	oldest, newest, ok := windowBounds(spOnly)
	if !ok {
		return []types.Finding{finding}
	}

	// The baseline is everything before the recent window. Too short a
	// baseline means no baseline — say nothing rather than guess.
	recentStart := newest.Add(-baselineRecentWindow)
	baselineDays := recentStart.Sub(oldest).Hours() / 24
	if baselineDays < baselineMinDays {
		return []types.Finding{finding}
	}

	for i := range spOnly {
		ev := &spOnly[i]
		acc := byApp[ev.AppID]
		if acc == nil {
			acc = &spEvents{appName: ev.AppDisplayName}
			byApp[ev.AppID] = acc
		}
		if acc.appName == "" {
			acc.appName = ev.AppDisplayName
		}
		if ev.CreatedDateTime.Before(recentStart) {
			acc.baseline++
			continue
		}
		acc.recent++
		if ev.CreatedDateTime.After(acc.lastSeen) {
			acc.lastSeen = ev.CreatedDateTime
		}
	}

	var affected []types.AffectedEntity
	for appID, acc := range byApp {
		if acc.recent < spSpikeMinRecentEvents {
			continue
		}
		// No baseline activity at all is a NEW service principal, not a spike.
		// Reporting it would be the "absence of data = finding" mistake: we
		// cannot tell a fresh legitimate integration from a compromise.
		if acc.baseline == 0 {
			continue
		}
		baselineRate := float64(acc.baseline) / baselineDays
		recentRate := float64(acc.recent) / (baselineRecentWindow.Hours() / 24)
		if baselineRate <= 0 || recentRate < baselineRate*spSpikeRatio {
			continue
		}
		if data.IncludeDetails {
			affected = append(affected, newSPSignInRiskEntity(appID, acc.appName, map[string]any{
				"appId":            appID,
				"appDisplayName":   acc.appName,
				"recentSignIns":    acc.recent,
				"baselineSignIns":  acc.baseline,
				"baselineDays":     round1(baselineDays),
				"recentPerDay":     round1(recentRate),
				"baselinePerDay":   round1(baselineRate),
				"spikeFactor":      round1(recentRate / baselineRate),
				"lastSignIn":       formatTime(acc.lastSeen),
				"windowStart":      formatTime(oldest),
				"recentWindowFrom": formatTime(recentStart),
			}))
		}
		finding.Count++
	}
	sortAffectedByDN(affected)
	finding.AffectedEntities = affected
	if finding.Count == 1 && len(affected) == 1 {
		c := affected[0].Azure.SignInRiskContext
		finding.Description = fmt.Sprintf(
			"Service principal %v signed in %v times in the last 24 hours, %v× its rate over the preceding %v days of the collected window (Graph retains 30 days at most, so the baseline spans days, not months).",
			c["appDisplayName"], c["recentSignIns"], c["spikeFactor"], c["baselineDays"],
		)
	}
	return []types.Finding{finding}
}

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
	// without saying why would be worse — so the guard is explicit.
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
			// this admin usually signs in — it must not narrow the known set.
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

// sortedKeys returns the map keys sorted, for deterministic evidence.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortAffectedByDN keeps the entity order deterministic for non-user entities
// (map iteration order would otherwise leak into the audit JSON).
func sortAffectedByDN(entities []types.AffectedEntity) {
	sort.Slice(entities, func(i, j int) bool { return entities[i].DN < entities[j].DN })
}

func init() {
	audit.MustRegister(NewSPSignInSpikeDetector())
	audit.MustRegister(NewUnusualGeoAdminDetector())
}
