package signinevents

import (
	"context"
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DeviceCodeFlowUsageDetector: the "frequently abused for phishing" framing
// is confirmed by Microsoft's own guidance, not a product claim. Microsoft
// Security Blog's coverage of Storm-2372 (microsoft.com/en-us/security/blog/
// 2025/02/13/storm-2372-conducts-device-code-phishing-campaign) documents
// device code flow abuse for credential and token theft, and Microsoft
// recommends blocking or restricting the flow via Conditional Access wherever
// it isn't explicitly required.
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

func init() {
	audit.MustRegister(NewDeviceCodeFlowUsageDetector())
}
