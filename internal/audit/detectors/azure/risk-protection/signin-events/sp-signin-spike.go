package signinevents

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
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
// The generic marshaller - the same fallback newIPRiskEntity relies on for
// "ip_address" - does merge it. Fixing the servicePrincipal marshaller means
// touching shared core, which is out of scope here.
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
	// baseline means no baseline - say nothing rather than guess.
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

func init() {
	audit.MustRegister(NewSPSignInSpikeDetector())
}

// sortAffectedByDN keeps the entity order deterministic for non-user entities
// (map iteration order would otherwise leak into the audit JSON).
func sortAffectedByDN(entities []types.AffectedEntity) {
	sort.Slice(entities, func(i, j int) bool { return entities[i].DN < entities[j].DN })
}
