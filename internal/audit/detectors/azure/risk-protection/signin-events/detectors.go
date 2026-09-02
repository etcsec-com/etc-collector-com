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

type PushFatigueDetector struct {
	audit.BaseDetector
}

func NewPushFatigueDetector() *PushFatigueDetector {
	return &PushFatigueDetector{BaseDetector: audit.NewBaseDetector(RISK_PUSH_FATIGUE, audit.CategoryRiskProtection)}
}

func (d *PushFatigueDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "MFA Push Fatigue Pattern",
		Description: "A user received many MFA push prompts in a short window with several failed or denied prompts.",
		Count:       0,
	}
	if len(data.AzureSignInLogs) == 0 {
		return []types.Finding{finding}
	}

	type promptRecord struct {
		at     time.Time
		ev     *types.SignInLog
		ip     string
		denied bool
	}
	byUser := map[string][]promptRecord{}
	for i := range data.AzureSignInLogs {
		ev := &data.AzureSignInLogs[i]
		key := userKey(ev)
		if key == "" {
			continue
		}
		for _, detail := range ev.AuthenticationDetails {
			if !isMFAPushPrompt(detail) {
				continue
			}
			at := detail.AuthenticationStepDateTime
			if at.IsZero() {
				at = ev.CreatedDateTime
			}
			byUser[key] = append(byUser[key], promptRecord{
				at:     at,
				ev:     ev,
				ip:     ev.IPAddress,
				denied: !detail.Succeeded,
			})
		}
	}

	var affected []types.AffectedEntity
	for _, records := range byUser {
		sort.Slice(records, func(i, j int) bool { return records[i].at.Before(records[j].at) })
		type bestWindow struct {
			promptCount int
			deniedCount int
			start       time.Time
			end         time.Time
			ev          *types.SignInLog
			sourceIPs   []string
		}
		var best bestWindow
		ipCounts := map[string]int{}
		deniedCount := 0
		start := 0
		for end := range records {
			rec := records[end]
			if rec.ip != "" {
				ipCounts[rec.ip]++
			}
			if rec.denied {
				deniedCount++
			}
			for start <= end && rec.at.Sub(records[start].at) > pushFatigueWindow {
				old := records[start]
				if old.ip != "" {
					ipCounts[old.ip]--
					if ipCounts[old.ip] <= 0 {
						delete(ipCounts, old.ip)
					}
				}
				if old.denied {
					deniedCount--
				}
				start++
			}
			promptCount := end - start + 1
			if promptCount < pushFatiguePromptMin || deniedCount < pushFatigueDeniedMin {
				continue
			}
			if promptCount > best.promptCount || (promptCount == best.promptCount && deniedCount > best.deniedCount) {
				best = bestWindow{
					promptCount: promptCount,
					deniedCount: deniedCount,
					start:       records[start].at,
					end:         rec.at,
					ev:          rec.ev,
					sourceIPs:   keysSorted(ipCounts),
				}
			}
		}
		if best.promptCount == 0 {
			continue
		}
		if data.IncludeDetails {
			affected = append(affected, newUserRiskEntity(best.ev, map[string]any{
				"promptCount": best.promptCount,
				"deniedCount": best.deniedCount,
				"windowStart": formatTime(best.start),
				"windowEnd":   formatTime(best.end),
				"sourceIps":   best.sourceIPs,
			}))
		}
		finding.Count++
	}
	sortAffectedUsers(affected)
	finding.AffectedEntities = affected
	if finding.Count == 1 && len(affected) == 1 {
		ctx := affected[0].Azure.SignInRiskContext
		finding.Description = fmt.Sprintf("User received %d MFA push prompts with %d denials in a short window, indicating likely MFA fatigue.", ctx["promptCount"], ctx["deniedCount"])
	}
	return []types.Finding{finding}
}

type ImpossibleTravelDetector struct {
	audit.BaseDetector
}

func NewImpossibleTravelDetector() *ImpossibleTravelDetector {
	return &ImpossibleTravelDetector{BaseDetector: audit.NewBaseDetector(RISK_IMPOSSIBLE_TRAVEL, audit.CategoryRiskProtection)}
}

func (d *ImpossibleTravelDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	severity := types.SeverityHigh
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    severity,
		Category:    string(d.Category()),
		Title:       "Impossible Travel Sign-In Pattern",
		Description: "A user signed in from distant countries too quickly for normal travel.",
		Count:       0,
	}
	if len(data.AzureSignInLogs) == 0 {
		return []types.Finding{finding}
	}

	admins := buildAdminUserSet(data.AzureRoleAssignments)
	var affected []types.AffectedEntity
	hasAdmin := false
	for _, events := range groupEventsByUser(data.AzureSignInLogs) {
		sortEvents(events)
		type bestPair struct {
			from     *types.SignInLog
			to       *types.SignInLog
			deltaSec int64
			distance float64
			speed    float64
			isAdmin  bool
		}
		var best bestPair
		for i := 1; i < len(events); i++ {
			from := events[i-1]
			to := events[i]
			if isCrossTenant(from) || isCrossTenant(to) {
				continue
			}
			fromCountry := locationCountry(from)
			toCountry := locationCountry(to)
			distance, ok := distanceBetweenCountries(fromCountry, toCountry)
			if !ok {
				continue
			}
			delta := to.CreatedDateTime.Sub(from.CreatedDateTime)
			if delta <= 0 {
				continue
			}
			speed := distance / delta.Hours()
			if speed <= impossibleTravelMinKmh {
				continue
			}
			isAdmin := admins[strings.ToLower(strings.TrimSpace(to.UserID))] || admins[strings.ToLower(strings.TrimSpace(to.UserPrincipalName))]
			if speed > best.speed {
				best = bestPair{
					from:     from,
					to:       to,
					deltaSec: int64(delta.Seconds()),
					distance: distance,
					speed:    speed,
					isAdmin:  isAdmin,
				}
			}
		}
		if best.speed == 0 {
			continue
		}
		finding.Count++
		if best.isAdmin {
			hasAdmin = true
		}
		if data.IncludeDetails {
			affected = append(affected, newUserRiskEntity(best.to, map[string]any{
				"isAdmin":          best.isAdmin,
				"fromCity":         best.from.Location.City,
				"fromCountry":      best.from.Location.CountryOrRegion,
				"toCity":           best.to.Location.City,
				"toCountry":        best.to.Location.CountryOrRegion,
				"deltaSeconds":     best.deltaSec,
				"distanceKm":       round1(best.distance),
				"computedSpeedKmh": round1(best.speed),
				"fromIp":           best.from.IPAddress,
				"toIp":             best.to.IPAddress,
			}))
		}
	}
	if hasAdmin {
		finding.Severity = types.SeverityCritical
		finding.Description = "An administrative user signed in from distant countries too quickly for normal travel."
	}
	sortAffectedUsers(affected)
	finding.AffectedEntities = affected
	return []types.Finding{finding}
}

type AITMTokenReplayDetector struct {
	audit.BaseDetector
}

func NewAITMTokenReplayDetector() *AITMTokenReplayDetector {
	return &AITMTokenReplayDetector{BaseDetector: audit.NewBaseDetector(RISK_AITM_TOKEN_REPLAY, audit.CategoryRiskProtection)}
}

func (d *AITMTokenReplayDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Possible AITM Token Replay",
		Description: "The same sign-in correlation ID appeared from geographically distant IPs in a short time window.",
		Count:       0,
	}
	if len(data.AzureSignInLogs) == 0 {
		return []types.Finding{finding}
	}

	byCorrelation := map[string][]*types.SignInLog{}
	for i := range data.AzureSignInLogs {
		ev := &data.AzureSignInLogs[i]
		corr := strings.TrimSpace(ev.CorrelationID)
		if corr == "" {
			continue
		}
		byCorrelation[corr] = append(byCorrelation[corr], ev)
	}

	var affected []types.AffectedEntity
	for corr, events := range byCorrelation {
		if len(events) < 2 {
			continue
		}
		sortEvents(events)
		type bestPair struct {
			original *types.SignInLog
			replay   *types.SignInLog
			deltaSec int64
			distance float64
		}
		var best bestPair
		for i := 0; i < len(events); i++ {
			for j := i + 1; j < len(events); j++ {
				delta := events[j].CreatedDateTime.Sub(events[i].CreatedDateTime)
				if delta <= 0 {
					continue
				}
				if delta >= aitmReplayWindow {
					break
				}
				if events[i].IPAddress == "" || events[j].IPAddress == "" || events[i].IPAddress == events[j].IPAddress {
					continue
				}
				distance, ok := distanceBetweenCountries(locationCountry(events[i]), locationCountry(events[j]))
				if !ok || distance <= aitmReplayMinDistanceKm {
					continue
				}
				if distance > best.distance {
					best = bestPair{
						original: events[i],
						replay:   events[j],
						deltaSec: int64(delta.Seconds()),
						distance: distance,
					}
				}
			}
		}
		if best.distance == 0 {
			continue
		}
		finding.Count++
		if data.IncludeDetails {
			tokenIssuerType := best.replay.TokenIssuerType
			if tokenIssuerType == "" {
				tokenIssuerType = best.original.TokenIssuerType
			}
			incomingTokenType := best.replay.IncomingTokenType
			if incomingTokenType == "" {
				incomingTokenType = best.original.IncomingTokenType
			}
			riskCtx := map[string]any{
				"correlationId":    corr,
				"originalIp":       best.original.IPAddress,
				"originalLocation": locationLabel(best.original.Location),
				"replayIp":         best.replay.IPAddress,
				"replayLocation":   locationLabel(best.replay.Location),
				"deltaSeconds":     best.deltaSec,
				"distanceKm":       round1(best.distance),
			}
			if tokenIssuerType != "" {
				riskCtx["tokenIssuerType"] = tokenIssuerType
			}
			if incomingTokenType != "" {
				riskCtx["incomingTokenType"] = incomingTokenType
			}
			affected = append(affected, newUserRiskEntity(best.replay, riskCtx))
		}
	}
	sortAffectedUsers(affected)
	finding.AffectedEntities = affected
	return []types.Finding{finding}
}

type DeviceCodeFlowUsageDetector struct {
	audit.BaseDetector
}

func NewDeviceCodeFlowUsageDetector() *DeviceCodeFlowUsageDetector {
	return &DeviceCodeFlowUsageDetector{BaseDetector: audit.NewBaseDetector(RISK_DEVICE_CODE_FLOW_USAGE, audit.CategoryRiskProtection)}
}

func (d *DeviceCodeFlowUsageDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Device Code Flow Sign-In Usage",
		Description: "Device code flow was used for one or more user sign-ins. This flow is frequently abused for phishing.",
		Count:       0,
	}
	if len(data.AzureSignInLogs) == 0 {
		return []types.Finding{finding}
	}

	type usage struct {
		ev    *types.SignInLog
		count int
		last  time.Time
		apps  []string
	}
	byUser := map[string]*usage{}
	for i := range data.AzureSignInLogs {
		ev := &data.AzureSignInLogs[i]
		if !strings.EqualFold(strings.TrimSpace(ev.AuthenticationProtocol), "deviceCode") {
			continue
		}
		key := userKey(ev)
		if key == "" {
			continue
		}
		u := byUser[key]
		if u == nil {
			u = &usage{ev: ev}
			byUser[key] = u
		}
		u.count++
		if ev.CreatedDateTime.After(u.last) {
			u.last = ev.CreatedDateTime
			u.ev = ev
		}
		if ev.AppDisplayName != "" {
			u.apps = append(u.apps, ev.AppDisplayName)
		}
	}

	var affected []types.AffectedEntity
	for _, u := range byUser {
		finding.Count++
		if data.IncludeDetails {
			affected = append(affected, newUserRiskEntity(u.ev, map[string]any{
				"attemptCount": u.count,
				"lastAttempt":  formatTime(u.last),
				"appsUsed":     uniqueSorted(u.apps),
			}))
		}
	}
	sortAffectedUsers(affected)
	finding.AffectedEntities = affected
	return []types.Finding{finding}
}

type LegacyAuthFromUserDetector struct {
	audit.BaseDetector
}

func NewLegacyAuthFromUserDetector() *LegacyAuthFromUserDetector {
	return &LegacyAuthFromUserDetector{BaseDetector: audit.NewBaseDetector(RISK_LEGACY_AUTH_FROM_USER, audit.CategoryRiskProtection)}
}

func (d *LegacyAuthFromUserDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Legacy Authentication Used by User",
		Description: "One or more users actually used legacy authentication protocols that cannot satisfy modern MFA controls.",
		Count:       0,
	}
	if len(data.AzureSignInLogs) == 0 {
		return []types.Finding{finding}
	}

	type legacyUse struct {
		ev           *types.SignInLog
		clientApp    string
		count        int
		successCount int
		failureCount int
		lastUse      time.Time
	}
	byUserClient := map[string]*legacyUse{}
	for i := range data.AzureSignInLogs {
		ev := &data.AzureSignInLogs[i]
		clientApp := strings.TrimSpace(ev.ClientAppUsed)
		if !isLegacyClientApp(clientApp) {
			continue
		}
		key := userKey(ev)
		if key == "" {
			continue
		}
		k := key + "\x00" + strings.ToLower(clientApp)
		u := byUserClient[k]
		if u == nil {
			u = &legacyUse{ev: ev, clientApp: clientApp}
			byUserClient[k] = u
		}
		u.count++
		if signInSuccess(ev) {
			u.successCount++
		} else {
			u.failureCount++
		}
		if ev.CreatedDateTime.After(u.lastUse) {
			u.lastUse = ev.CreatedDateTime
			u.ev = ev
		}
	}

	var affected []types.AffectedEntity
	for _, u := range byUserClient {
		finding.Count++
		if data.IncludeDetails {
			affected = append(affected, newUserRiskEntity(u.ev, map[string]any{
				"clientApp":    u.clientApp,
				"count":        u.count,
				"lastUse":      formatTime(u.lastUse),
				"successCount": u.successCount,
				"failureCount": u.failureCount,
			}))
		}
	}
	sortAffectedUsers(affected)
	finding.AffectedEntities = affected
	return []types.Finding{finding}
}

type FailedSignInBurstDetector struct {
	audit.BaseDetector
}

func NewFailedSignInBurstDetector() *FailedSignInBurstDetector {
	return &FailedSignInBurstDetector{BaseDetector: audit.NewBaseDetector(RISK_FAILED_SIGNIN_BURST, audit.CategoryRiskProtection)}
}

func (d *FailedSignInBurstDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	targeted := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Failed Sign-In Burst",
		Description: "A burst of invalid-credential sign-in failures indicates targeted brute force or password spray activity.",
		Count:       0,
		Details:     map[string]interface{}{"patternType": "targeted_bruteforce"},
	}
	spray := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Failed Sign-In Burst",
		Description: "A burst of invalid-credential sign-in failures from one IP across many users indicates password spray activity.",
		Count:       0,
		Details:     map[string]interface{}{"patternType": "password_spray"},
	}
	if len(data.AzureSignInLogs) == 0 {
		return []types.Finding{targeted, spray}
	}

	failures := make([]types.SignInLog, 0)
	for i := range data.AzureSignInLogs {
		if isCredentialFailure(&data.AzureSignInLogs[i]) {
			failures = append(failures, data.AzureSignInLogs[i])
		}
	}
	targeted.AffectedEntities = detectTargetedBruteforce(failures, data.IncludeDetails, &targeted.Count)
	spray.AffectedEntities = detectPasswordSpray(failures, data.IncludeDetails, &spray.Count)
	return []types.Finding{targeted, spray}
}

func init() {
	audit.MustRegister(NewPushFatigueDetector())
	audit.MustRegister(NewImpossibleTravelDetector())
	audit.MustRegister(NewAITMTokenReplayDetector())
	audit.MustRegister(NewDeviceCodeFlowUsageDetector())
	audit.MustRegister(NewLegacyAuthFromUserDetector())
	audit.MustRegister(NewFailedSignInBurstDetector())
}

func detectTargetedBruteforce(failures []types.SignInLog, includeDetails bool, count *int) []types.AffectedEntity {
	byUser := groupEventsByUser(failures)
	var affected []types.AffectedEntity
	for _, events := range byUser {
		sortEvents(events)
		type bestWindow struct {
			failures int
			start    time.Time
			end      time.Time
			ev       *types.SignInLog
			ips      []string
			codes    []int
		}
		var best bestWindow
		ipCounts := map[string]int{}
		codeCounts := map[int]int{}
		start := 0
		for end, ev := range events {
			if ev.IPAddress != "" {
				ipCounts[ev.IPAddress]++
			}
			codeCounts[ev.Status.ErrorCode]++
			for start <= end && ev.CreatedDateTime.Sub(events[start].CreatedDateTime) > failedBurstWindow {
				old := events[start]
				if old.IPAddress != "" {
					ipCounts[old.IPAddress]--
					if ipCounts[old.IPAddress] <= 0 {
						delete(ipCounts, old.IPAddress)
					}
				}
				codeCounts[old.Status.ErrorCode]--
				if codeCounts[old.Status.ErrorCode] <= 0 {
					delete(codeCounts, old.Status.ErrorCode)
				}
				start++
			}
			failureCount := end - start + 1
			if failureCount < failedBurstMinFailures || failureCount <= best.failures {
				continue
			}
			best = bestWindow{
				failures: failureCount,
				start:    events[start].CreatedDateTime,
				end:      ev.CreatedDateTime,
				ev:       ev,
				ips:      keysSorted(ipCounts),
				codes:    codesSortedFromCounts(codeCounts),
			}
		}
		if best.failures == 0 {
			continue
		}
		*count++
		if includeDetails {
			affected = append(affected, newUserRiskEntity(best.ev, map[string]any{
				"patternType":  "targeted_bruteforce",
				"failureCount": best.failures,
				"windowStart":  formatTime(best.start),
				"windowEnd":    formatTime(best.end),
				"sourceIps":    best.ips,
				"errorCodes":   best.codes,
			}))
		}
	}
	sortAffectedUsers(affected)
	return affected
}

func detectPasswordSpray(failures []types.SignInLog, includeDetails bool, count *int) []types.AffectedEntity {
	byIP := groupEventsByIP(failures)
	var affected []types.AffectedEntity
	for ip, events := range byIP {
		sortEvents(events)
		type bestWindow struct {
			failures      int
			distinctUsers int
			start         time.Time
			end           time.Time
			topTargets    []string
		}
		var best bestWindow
		userCounts := map[string]int{}
		start := 0
		for end, ev := range events {
			u := userDisplay(ev)
			userCounts[u]++
			for start <= end && ev.CreatedDateTime.Sub(events[start].CreatedDateTime) > failedBurstWindow {
				oldUser := userDisplay(events[start])
				userCounts[oldUser]--
				if userCounts[oldUser] <= 0 {
					delete(userCounts, oldUser)
				}
				start++
			}
			failureCount := end - start + 1
			distinctUsers := len(userCounts)
			if failureCount < failedBurstMinFailures || distinctUsers < failedBurstMinUsers {
				continue
			}
			if failureCount < best.failures || (failureCount == best.failures && distinctUsers <= best.distinctUsers) {
				continue
			}
			best = bestWindow{
				failures:      failureCount,
				distinctUsers: distinctUsers,
				start:         events[start].CreatedDateTime,
				end:           ev.CreatedDateTime,
				topTargets:    topTargets(userCounts, 10),
			}
		}
		if best.failures == 0 {
			continue
		}
		*count++
		if includeDetails {
			affected = append(affected, newIPRiskEntity(ip, map[string]any{
				"ipAddress":     ip,
				"patternType":   "password_spray",
				"failureCount":  best.failures,
				"distinctUsers": best.distinctUsers,
				"windowStart":   formatTime(best.start),
				"windowEnd":     formatTime(best.end),
				"topTargets":    best.topTargets,
			}))
		}
	}
	sort.Slice(affected, func(i, j int) bool { return affected[i].DN < affected[j].DN })
	return affected
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

func codesSortedFromCounts(m map[int]int) []int {
	out := make([]int, 0, len(m))
	for k, v := range m {
		if v > 0 {
			out = append(out, k)
		}
	}
	sort.Ints(out)
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
