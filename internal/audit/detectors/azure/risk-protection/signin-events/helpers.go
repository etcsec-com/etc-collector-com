package signinevents

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	RISK_PUSH_FATIGUE           = "RISK_PUSH_FATIGUE"
	RISK_IMPOSSIBLE_TRAVEL      = "RISK_IMPOSSIBLE_TRAVEL"
	RISK_AITM_TOKEN_REPLAY      = "RISK_AITM_TOKEN_REPLAY"
	RISK_DEVICE_CODE_FLOW_USAGE = "RISK_DEVICE_CODE_FLOW_USAGE"
	RISK_LEGACY_AUTH_FROM_USER  = "RISK_LEGACY_AUTH_FROM_USER"
	RISK_FAILED_SIGNIN_BURST    = "RISK_FAILED_SIGNIN_BURST"

	pushFatigueWindow       = 5 * time.Minute
	pushFatiguePromptMin    = 10
	pushFatigueDeniedMin    = 3
	impossibleTravelMinKmh  = 850.0
	aitmReplayWindow        = 30 * time.Minute
	aitmReplayMinDistanceKm = 500.0
	failedBurstWindow       = 10 * time.Minute
	failedBurstMinFailures  = 50
	failedBurstMinUsers     = 10
)

var privilegedRoleIDs = map[string]bool{
	types.AzureRoleGlobalAdmin:            true,
	types.AzureRoleSecurityAdmin:          true,
	types.AzureRolePrivilegedRoleAdmin:    true,
	types.AzureRoleUserAdmin:              true,
	types.AzureRoleExchangeAdmin:          true,
	types.AzureRoleSharePointAdmin:        true,
	types.AzureRoleCloudAppAdmin:          true,
	types.AzureRoleAppAdmin:               true,
	types.AzureRoleConditionalAccessAdmin: true,
}

func userKey(ev *types.SignInLog) string {
	if ev == nil {
		return ""
	}
	if ev.UserID != "" {
		return strings.ToLower(strings.TrimSpace(ev.UserID))
	}
	return strings.ToLower(strings.TrimSpace(ev.UserPrincipalName))
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

func round0(v float64) float64 {
	return math.Round(v)
}

func newUserRiskEntity(ev *types.SignInLog, ctx map[string]any) types.AffectedEntity {
	id := ev.UserID
	if id == "" {
		id = ev.UserPrincipalName
	}
	return types.AffectedEntity{
		Type:              "user",
		DN:                id,
		SAMAccountName:    ev.UserPrincipalName,
		UserPrincipalName: ev.UserPrincipalName,
		DisplayName:       ev.UserDisplayName,
		Azure: &types.AzureEntityFields{
			SignInRiskContext: ctx,
		},
	}
}

func newIPRiskEntity(ip string, ctx map[string]any) types.AffectedEntity {
	return types.AffectedEntity{
		Type:        "ip_address",
		DN:          ip,
		Name:        ip,
		DisplayName: ip,
		Azure: &types.AzureEntityFields{
			SignInRiskContext: ctx,
		},
	}
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sortedErrorCodes(codes map[int]struct{}) []int {
	out := make([]int, 0, len(codes))
	for code := range codes {
		out = append(out, code)
	}
	sort.Ints(out)
	return out
}

func topTargets(userCounts map[string]int, limit int) []string {
	type pair struct {
		user  string
		count int
	}
	pairs := make([]pair, 0, len(userCounts))
	for user, count := range userCounts {
		if user == "" {
			continue
		}
		pairs = append(pairs, pair{user: user, count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].user < pairs[j].user
	})
	if len(pairs) > limit {
		pairs = pairs[:limit]
	}
	out := make([]string, len(pairs))
	for i := range pairs {
		out[i] = pairs[i].user
	}
	return out
}

func signInSuccess(ev *types.SignInLog) bool {
	return ev != nil && ev.Status != nil && ev.Status.ErrorCode == 0
}

func isCredentialFailure(ev *types.SignInLog) bool {
	if ev == nil || ev.Status == nil {
		return false
	}
	return ev.Status.ErrorCode == 50126 || ev.Status.ErrorCode == 50056
}

func isLegacyClientApp(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "other clients",
		"authenticated smtp",
		"smtp",
		"exchange activesync",
		"imap",
		"pop",
		"mapi",
		"mapi over http",
		"offline address book",
		"outlook anywhere (rpc over http)",
		"exchange online powershell",
		"exchange web services",
		"reporting web services",
		"autodiscover":
		return true
	}
	return false
}

func isMFAPushPrompt(detail types.SignInAuthDetail) bool {
	text := strings.ToLower(strings.Join([]string{
		detail.AuthenticationMethod,
		detail.AuthenticationMethodDetail,
		detail.AuthenticationStepResultDetail,
	}, " "))
	if text == "" || strings.Contains(text, "password") {
		return false
	}
	return strings.Contains(text, "push") ||
		strings.Contains(text, "notification") ||
		strings.Contains(text, "authenticator app") ||
		strings.Contains(text, "mobile app")
}

func isCrossTenant(ev *types.SignInLog) bool {
	if ev == nil {
		return false
	}
	v := strings.TrimSpace(ev.CrossTenantAccessType)
	return v != "" && !strings.EqualFold(v, "none")
}

func locationCountry(ev *types.SignInLog) string {
	if ev == nil || ev.Location == nil {
		return ""
	}
	return strings.TrimSpace(ev.Location.CountryOrRegion)
}

func locationLabel(loc *types.SignInLocation) string {
	if loc == nil {
		return ""
	}
	parts := make([]string, 0, 2)
	if loc.City != "" {
		parts = append(parts, loc.City)
	}
	if loc.CountryOrRegion != "" {
		parts = append(parts, loc.CountryOrRegion)
	}
	return strings.Join(parts, ", ")
}

func countryCentroid(country string) (lat, lon float64, ok bool) {
	key := normalizeCountry(country)
	if key == "" {
		return 0, 0, false
	}
	coords, ok := countryCentroids[key]
	if !ok {
		return 0, 0, false
	}
	return coords[0], coords[1], true
}

func normalizeCountry(country string) string {
	v := strings.ToUpper(strings.TrimSpace(country))
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, "_", " ")
	v = strings.Join(strings.Fields(v), " ")
	if len(v) == 2 {
		return v
	}
	if alias, ok := countryNameAliases[v]; ok {
		return alias
	}
	return v
}

func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0
	toRad := func(deg float64) float64 { return deg * math.Pi / 180 }
	dLat := toRad(lat2 - lat1)
	dLon := toRad(lon2 - lon1)
	rlat1 := toRad(lat1)
	rlat2 := toRad(lat2)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rlat1)*math.Cos(rlat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return earthRadiusKm * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

func distanceBetweenCountries(from, to string) (float64, bool) {
	fromKey := normalizeCountry(from)
	toKey := normalizeCountry(to)
	if fromKey == "" || toKey == "" || fromKey == toKey {
		return 0, false
	}
	lat1, lon1, ok := countryCentroid(fromKey)
	if !ok {
		return 0, false
	}
	lat2, lon2, ok := countryCentroid(toKey)
	if !ok {
		return 0, false
	}
	return haversineKm(lat1, lon1, lat2, lon2), true
}

func buildAdminUserSet(assignments []types.RoleAssignment) map[string]bool {
	admins := make(map[string]bool)
	for _, ra := range assignments {
		if !privilegedRoleIDs[ra.RoleID] {
			continue
		}
		if ra.PrincipalType != "" && !strings.EqualFold(ra.PrincipalType, "User") {
			continue
		}
		if id := strings.ToLower(strings.TrimSpace(ra.PrincipalID)); id != "" {
			admins[id] = true
		}
		if upn := strings.ToLower(strings.TrimSpace(ra.UserPrincipalName)); upn != "" {
			admins[upn] = true
		}
	}
	return admins
}

func sortEvents(events []*types.SignInLog) {
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedDateTime.Before(events[j].CreatedDateTime)
	})
}

func groupEventsByUser(logs []types.SignInLog) map[string][]*types.SignInLog {
	out := make(map[string][]*types.SignInLog)
	for i := range logs {
		key := userKey(&logs[i])
		if key == "" {
			continue
		}
		out[key] = append(out[key], &logs[i])
	}
	return out
}

func groupEventsByIP(logs []types.SignInLog) map[string][]*types.SignInLog {
	out := make(map[string][]*types.SignInLog)
	for i := range logs {
		ip := strings.TrimSpace(logs[i].IPAddress)
		if ip == "" {
			continue
		}
		out[ip] = append(out[ip], &logs[i])
	}
	return out
}

func userDisplay(ev *types.SignInLog) string {
	if ev == nil {
		return ""
	}
	if ev.UserPrincipalName != "" {
		return ev.UserPrincipalName
	}
	if ev.UserID != "" {
		return ev.UserID
	}
	return "unknown-user"
}

func intKey(code int) string {
	return strconv.Itoa(code)
}

func keysSorted(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if k != "" && v > 0 {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sortAffectedUsers(affected []types.AffectedEntity) {
	sort.Slice(affected, func(i, j int) bool {
		if affected[i].UserPrincipalName != affected[j].UserPrincipalName {
			return affected[i].UserPrincipalName < affected[j].UserPrincipalName
		}
		return affected[i].DN < affected[j].DN
	})
}

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
// work, which is a separate ticket - until it lands, an in-window baseline is
// the honest maximum.
//
// The consequence is stated in each finding's description, so a reader knows
// the comparison covers days and not months.

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

	// spSpikeRatio, spSpikeMinRecentEvents, baselineMinDays and
	// geoMinBaselineSignIns are this product's own engineering thresholds
	// for anomaly detection over the collected sign-in stream, not values
	// prescribed by a Microsoft, CIS, or ANSII document. No official source
	// publishes a numeric baseline-window, spike-ratio, or minimum-sample
	// figure for detecting a service-principal sign-in rate change or an
	// admin's first sign-in from a new country from raw /auditLogs/signIns
	// data - that kind of anomaly detection is what Microsoft's own paid
	// ML-based products (Identity Protection risk detections) do internally,
	// without publishing the thresholds. These constants are named plainly
	// as engineering judgment in the titles/descriptions below (never
	// attributed to a referential requirement) and are tunable product
	// parameters, not compliance gaps against an external norm.
)

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
// what gets dropped is the OLDEST end - precisely the baseline. Computing a
// ratio against a partially collected baseline inflates it, which would turn a
// collection limit into a stream of false positives.
//
// Emitting nothing would be just as wrong: a clean report would then be
// indistinguishable from an unanalysed one. So the finding is emitted at Info
// severity - visible in the report, zero weight in the score - saying the
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
		Title:    title + " - analysis skipped (incomplete data)",
		Description: fmt.Sprintf(
			"This check was NOT performed: %s. It compares recent activity against the earlier part of the same window, and truncation drops the oldest events first - the baseline. Running it anyway would report spikes that are collection artefacts. Raise --azure-signin-logs-max and --azure-signin-logs-budget, then re-run. This is not a clean result.",
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
