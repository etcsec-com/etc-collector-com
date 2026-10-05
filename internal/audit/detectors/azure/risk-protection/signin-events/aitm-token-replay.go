package signinevents

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AITMTokenReplayDetector is an etc-collector heuristic proxy, not a read of
// a named Microsoft detection. Microsoft's own AiTM-adjacent signals -
// "Anomalous Token" (riskEventType anomalousToken) and "Attacker in the
// Middle" (riskEventType attackerinTheMiddle) - are documented at a
// conceptual level (learn.microsoft.com/en-us/entra/id-protection/
// concept-identity-protection-risks, sections "Anomalous token (sign-in)" and
// "Attacker in the Middle") but their detection logic is Microsoft's
// proprietary ML, not published, so there is nothing to replicate against.
// This detector instead flags its own signal: the same sign-in
// correlationId reappearing from IP addresses far enough apart, inside a
// short window, that both couldn't plausibly be the same client session -
// a token-replay pattern documented by third-party AiTM detection research
// (e.g. Microsoft Incident Response guidance on investigating AiTM phishing
// recommends correlating sign-in session/correlation identifiers across
// IP/location for exactly this reason).
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

func init() {
	audit.MustRegister(NewAITMTokenReplayDetector())
}
