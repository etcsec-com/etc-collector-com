package signinevents

import (
	"context"
	"fmt"
	"sort"
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

func init() {
	audit.MustRegister(NewPushFatigueDetector())
}
