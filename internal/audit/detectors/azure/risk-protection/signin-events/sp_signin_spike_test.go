package signinevents

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// spSignIn builds a service-principal sign-in event at the given offset from
// testBaseTime (negative = older).
func spSignIn(appID string, offset time.Duration, opts ...func(*types.SignInLog)) types.SignInLog {
	ev := types.SignInLog{
		ID:               appID + "-" + offset.String(),
		CreatedDateTime:  testBaseTime.Add(offset),
		AppID:            appID,
		AppDisplayName:   "Backup Service",
		SignInEventTypes: []string{"servicePrincipal"},
		Status:           &types.SignInStatus{ErrorCode: 0},
		IPAddress:        "198.51.100.7",
	}
	for _, opt := range opts {
		opt(&ev)
	}
	return ev
}

// spStream lays down `baselineDays` days of `perDay` events for appID, then
// `recent` events inside the last 24 hours.
func spStream(appID string, baselineDays, perDay, recent int) []types.SignInLog {
	var logs []types.SignInLog
	// Baseline: spread over the days preceding the recent window. Day 0 is the
	// oldest, so the offsets run from -(baselineDays+1) days up to -1 day.
	for day := 0; day < baselineDays; day++ {
		base := -time.Duration(baselineDays+1-day) * 24 * time.Hour
		for i := 0; i < perDay; i++ {
			logs = append(logs, spSignIn(appID, base+time.Duration(i)*time.Minute))
		}
	}
	for i := 0; i < recent; i++ {
		logs = append(logs, spSignIn(appID, -time.Duration(i)*time.Minute))
	}
	return logs
}

func TestSPSignInSpikeDetector(t *testing.T) {
	det := NewSPSignInSpikeDetector()

	cases := []struct {
		name      string
		data      *audit.DetectorData
		wantCount int
		wantSev   types.Severity
		reason    string
	}{
		{
			name:      "no sign-in logs at all",
			data:      detectorData(nil),
			wantCount: 0,
			wantSev:   types.SeverityHigh,
			reason:    "no data must never be a finding",
		},
		{
			// 10 days × 1/day baseline, then 40 in the last day = 40× the rate.
			name:      "clear spike over an established baseline",
			data:      detectorData(spStream("app-1", 10, 1, 40)),
			wantCount: 1,
			wantSev:   types.SeverityHigh,
			reason:    "40/day against a 1/day baseline is the case this detector exists for",
		},
		{
			name:      "steady traffic is not a spike",
			data:      detectorData(spStream("app-1", 10, 30, 30)),
			wantCount: 0,
			wantSev:   types.SeverityHigh,
			reason:    "same rate on both sides of the split",
		},
		{
			// 3× is real movement but below the threshold — deliberately quiet.
			name:      "growth below the 5x threshold stays quiet",
			data:      detectorData(spStream("app-1", 10, 10, 30)),
			wantCount: 0,
			wantSev:   types.SeverityHigh,
			reason:    "3x must not fire",
		},
		{
			name:      "baseline too short to mean anything",
			data:      detectorData(spStream("app-1", 3, 1, 40)),
			wantCount: 0,
			wantSev:   types.SeverityHigh,
			reason:    "a 3-day window cannot establish what is normal",
		},
		{
			name:      "brand-new service principal is not a spike",
			data:      detectorData(append(spStream("app-other", 10, 5, 5), spStream("app-new", 0, 0, 40)...)),
			wantCount: 0,
			wantSev:   types.SeverityHigh,
			reason:    "zero baseline cannot distinguish a new integration from a compromise",
		},
		{
			name:      "spike below the absolute floor stays quiet",
			data:      detectorData(spStream("app-1", 20, 1, 10)),
			wantCount: 0,
			wantSev:   types.SeverityHigh,
			reason:    "10 events in a day is not worth waking anyone for, whatever the ratio",
		},
		{
			name: "interactive user sign-ins are not machine traffic",
			data: detectorData(func() []types.SignInLog {
				logs := spStream("app-1", 10, 1, 40)
				for i := range logs {
					logs[i].SignInEventTypes = []string{"interactiveUser"}
				}
				return logs
			}()),
			wantCount: 0,
			wantSev:   types.SeverityHigh,
			reason:    "a human using an app is not a service principal rate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := det.Detect(context.Background(), tc.data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Errorf("Count = %d, want %d (%s)", findings[0].Count, tc.wantCount, tc.reason)
			}
			if findings[0].Severity != tc.wantSev {
				t.Errorf("Severity = %s, want %s", findings[0].Severity, tc.wantSev)
			}
			if findings[0].Type != RISK_SP_SIGNIN_SPIKE {
				t.Errorf("Type = %s, want %s", findings[0].Type, RISK_SP_SIGNIN_SPIKE)
			}
		})
	}
}

// Truncation drops the OLDEST events first, which is exactly the baseline, so a
// ratio computed on a truncated stream is inflated. The detector must neither
// report that inflated spike nor return a clean result that reads as "checked,
// nothing found".
func TestSPSignInSpikeDetector_TruncatedStream(t *testing.T) {
	data := detectorData(spStream("app-1", 10, 1, 40))
	data.AzureSignInLogsTruncated = true
	data.AzureSignInLogsEventsCollected = 500000
	data.AzureSignInLogsRequestedDays = 30
	data.AzureSignInLogsActualDays = 30

	findings := NewSPSignInSpikeDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Severity == types.SeverityHigh {
		t.Error("truncated data must not produce the risk verdict — that would be a collection artefact reported as a spike")
	}
	if f.Severity != types.SeverityInfo {
		t.Errorf("Severity = %s, want info", f.Severity)
	}
	if f.Count == 0 {
		t.Error("Count 0 is filtered out by the engine — the skipped analysis would vanish and read as a clean result")
	}
	if got := f.Details["analysisSkipped"]; got != "signInLogsTruncated" {
		t.Errorf("Details[analysisSkipped] = %v, want signInLogsTruncated", got)
	}
	if got := f.Details["eventsCollected"]; got != 500000 {
		t.Errorf("Details[eventsCollected] = %v, want 500000", got)
	}
}

// The evidence must survive JSON marshalling. The canonical "servicePrincipal"
// entity type would silently drop SignInRiskContext (its marshaller does not
// merge it), which is why the detector uses a type that routes to the generic
// marshaller instead.
func TestSPSignInSpikeDetector_EvidenceSurvivesMarshalling(t *testing.T) {
	findings := NewSPSignInSpikeDetector().Detect(context.Background(), detectorData(spStream("app-1", 10, 1, 40)))
	if findings[0].Count != 1 || len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 affected entity, got count=%d entities=%d", findings[0].Count, len(findings[0].AffectedEntities))
	}

	body, err := json.Marshal(findings[0].AffectedEntities[0])
	if err != nil {
		t.Fatalf("marshal entity: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal entity: %v", err)
	}
	for _, key := range []string{"appId", "recentSignIns", "baselineSignIns", "baselinePerDay", "spikeFactor", "baselineDays"} {
		if _, ok := out[key]; !ok {
			t.Errorf("evidence key %q missing from the marshalled entity: %s", key, body)
		}
	}
	if got := out["spikeFactor"]; got != 40.0 {
		t.Errorf("spikeFactor = %v, want 40", got)
	}
}
