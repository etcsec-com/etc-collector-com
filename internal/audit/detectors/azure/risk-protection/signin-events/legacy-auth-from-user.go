package signinevents

import (
	"context"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

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

func init() {
	audit.MustRegister(NewLegacyAuthFromUserDetector())
}
