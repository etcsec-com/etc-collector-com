package signinevents

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

var testBaseTime = time.Date(2026, 5, 3, 14, 0, 0, 0, time.UTC)

func signIn(opts ...func(*types.SignInLog)) types.SignInLog {
	ev := types.SignInLog{
		ID:                     "event",
		CreatedDateTime:        testBaseTime,
		UserID:                 "user-1",
		UserPrincipalName:      "alice@example.com",
		UserDisplayName:        "Alice",
		AppDisplayName:         "Microsoft Office",
		ClientAppUsed:          "Browser",
		AuthenticationProtocol: "oAuth2",
		IPAddress:              "192.0.2.10",
		Location:               &types.SignInLocation{City: "Paris", CountryOrRegion: "FR"},
		Status:                 &types.SignInStatus{ErrorCode: 0},
		CrossTenantAccessType:  "none",
	}
	for _, opt := range opts {
		opt(&ev)
	}
	return ev
}

func detectorData(logs []types.SignInLog) *audit.DetectorData {
	return &audit.DetectorData{AzureSignInLogs: logs, IncludeDetails: true}
}

func TestHelpers_GeoAndAdmin(t *testing.T) {
	d := haversineKm(48.8566, 2.3522, -33.8688, 151.2093)
	if d < 16000 || d > 18000 {
		t.Fatalf("Paris-Sydney distance = %.1f, want roughly 17000km", d)
	}
	if _, ok := distanceBetweenCountries("FR", "FR"); ok {
		t.Fatalf("same-country distance should not be usable for impossible travel")
	}
	if _, _, ok := countryCentroid("France"); !ok {
		t.Fatalf("country alias France should resolve")
	}
	admins := buildAdminUserSet([]types.RoleAssignment{
		{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "user-1", UserPrincipalName: "admin@example.com", PrincipalType: "User"},
		{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "sp-1", PrincipalType: "ServicePrincipal"},
	})
	if !admins["user-1"] || !admins["admin@example.com"] {
		t.Fatalf("user admin assignment not indexed: %#v", admins)
	}
	if admins["sp-1"] {
		t.Fatalf("service principal admin assignment should not mark a user admin")
	}
}

func TestAffectedEntitySignInContextIsFlat(t *testing.T) {
	ev := signIn()
	entity := newUserRiskEntity(&ev, map[string]any{
		"promptCount": 15,
		"windowStart": "2026-05-03T14:00:00Z",
	})
	body, err := json.Marshal(entity)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["type"] != "user" || got["promptCount"].(float64) != 15 {
		t.Fatalf("flat context missing from JSON: %s", string(body))
	}
	if _, ok := got["azure"]; ok {
		t.Fatalf("sign-in context must be flat, got nested azure: %s", string(body))
	}
}

func TestPushFatigueDetector(t *testing.T) {
	var logs []types.SignInLog
	for i := 0; i < 10; i++ {
		i := i
		logs = append(logs, signIn(func(ev *types.SignInLog) {
			ev.ID = "push-" + time.Duration(i).String()
			ev.CreatedDateTime = testBaseTime.Add(time.Duration(i) * 20 * time.Second)
			ev.AuthenticationDetails = []types.SignInAuthDetail{{
				AuthenticationStepDateTime: ev.CreatedDateTime,
				AuthenticationMethod:       "Microsoft Authenticator app notification",
				Succeeded:                  i >= 3,
			}}
		}))
	}
	f := NewPushFatigueDetector().Detect(context.Background(), detectorData(logs))[0]
	if f.Count != 1 || len(f.AffectedEntities) != 1 {
		t.Fatalf("expected one push fatigue finding, got count=%d entities=%d", f.Count, len(f.AffectedEntities))
	}

	logs = logs[:9]
	f = NewPushFatigueDetector().Detect(context.Background(), detectorData(logs))[0]
	if f.Count != 0 {
		t.Fatalf("under-threshold prompts should not trigger, got %d", f.Count)
	}
}

func TestImpossibleTravelDetector(t *testing.T) {
	logs := []types.SignInLog{
		signIn(),
		signIn(func(ev *types.SignInLog) {
			ev.CreatedDateTime = testBaseTime.Add(10 * time.Minute)
			ev.IPAddress = "198.51.100.20"
			ev.Location = &types.SignInLocation{City: "Sydney", CountryOrRegion: "AU"}
		}),
	}
	data := detectorData(logs)
	data.AzureRoleAssignments = []types.RoleAssignment{
		{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "user-1", PrincipalType: "User"},
	}
	f := NewImpossibleTravelDetector().Detect(context.Background(), data)[0]
	if f.Count != 1 || f.Severity != types.SeverityCritical {
		t.Fatalf("expected critical admin impossible travel, got count=%d severity=%s", f.Count, f.Severity)
	}

	data.AzureSignInLogs[1].CrossTenantAccessType = "b2bCollaboration"
	f = NewImpossibleTravelDetector().Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("cross-tenant pair should be skipped, got %d", f.Count)
	}
}

func TestAITMTokenReplayDetector(t *testing.T) {
	logs := []types.SignInLog{
		signIn(func(ev *types.SignInLog) {
			ev.CorrelationID = "corr-1"
			ev.TokenIssuerType = "AzureAD"
			ev.IncomingTokenType = "primaryRefreshToken"
		}),
		signIn(func(ev *types.SignInLog) {
			ev.CorrelationID = "corr-1"
			ev.CreatedDateTime = testBaseTime.Add(5 * time.Minute)
			ev.IPAddress = "203.0.113.50"
			ev.Location = &types.SignInLocation{City: "Moscow", CountryOrRegion: "RU"}
		}),
	}
	f := NewAITMTokenReplayDetector().Detect(context.Background(), detectorData(logs))[0]
	if f.Count != 1 || len(f.AffectedEntities) != 1 {
		t.Fatalf("expected one AITM replay finding, got count=%d entities=%d", f.Count, len(f.AffectedEntities))
	}

	logs[1].IPAddress = logs[0].IPAddress
	f = NewAITMTokenReplayDetector().Detect(context.Background(), detectorData(logs))[0]
	if f.Count != 0 {
		t.Fatalf("same IP should not trigger AITM replay, got %d", f.Count)
	}
}

func TestDeviceCodeFlowUsageDetector(t *testing.T) {
	f := NewDeviceCodeFlowUsageDetector().Detect(context.Background(), detectorData([]types.SignInLog{
		signIn(func(ev *types.SignInLog) { ev.AuthenticationProtocol = "deviceCode" }),
	}))[0]
	if f.Count != 1 {
		t.Fatalf("deviceCode usage should trigger, got %d", f.Count)
	}
	f = NewDeviceCodeFlowUsageDetector().Detect(context.Background(), detectorData([]types.SignInLog{signIn()}))[0]
	if f.Count != 0 {
		t.Fatalf("oAuth2 should not trigger device code usage, got %d", f.Count)
	}
}

func TestLegacyAuthFromUserDetector(t *testing.T) {
	f := NewLegacyAuthFromUserDetector().Detect(context.Background(), detectorData([]types.SignInLog{
		signIn(func(ev *types.SignInLog) { ev.ClientAppUsed = "POP" }),
	}))[0]
	if f.Count != 1 {
		t.Fatalf("legacy auth should trigger, got %d", f.Count)
	}
	f = NewLegacyAuthFromUserDetector().Detect(context.Background(), detectorData([]types.SignInLog{signIn()}))[0]
	if f.Count != 0 {
		t.Fatalf("Browser should not trigger legacy auth, got %d", f.Count)
	}
}

func TestFailedSignInBurstTargeted(t *testing.T) {
	var logs []types.SignInLog
	for i := 0; i < 50; i++ {
		i := i
		logs = append(logs, signIn(func(ev *types.SignInLog) {
			ev.ID = "fail-target-" + time.Duration(i).String()
			ev.CreatedDateTime = testBaseTime.Add(time.Duration(i) * 5 * time.Second)
			ev.Status = &types.SignInStatus{ErrorCode: 50126}
		}))
	}
	findings := NewFailedSignInBurstDetector().Detect(context.Background(), detectorData(logs))
	if findings[0].Count != 1 {
		t.Fatalf("targeted brute force should trigger, got %d", findings[0].Count)
	}
	if findings[1].Count != 0 {
		t.Fatalf("single-user failures should not trigger password spray, got %d", findings[1].Count)
	}
}

func TestFailedSignInBurstPasswordSpray(t *testing.T) {
	var logs []types.SignInLog
	for i := 0; i < 50; i++ {
		i := i
		userNum := i % 10
		logs = append(logs, signIn(func(ev *types.SignInLog) {
			ev.ID = "fail-spray-" + time.Duration(i).String()
			ev.UserID = "user-" + string(rune('a'+userNum))
			ev.UserPrincipalName = string(rune('a'+userNum)) + "@example.com"
			ev.CreatedDateTime = testBaseTime.Add(time.Duration(i) * 5 * time.Second)
			ev.IPAddress = "203.0.113.80"
			ev.Status = &types.SignInStatus{ErrorCode: 50056}
		}))
	}
	findings := NewFailedSignInBurstDetector().Detect(context.Background(), detectorData(logs))
	if findings[1].Count != 1 {
		t.Fatalf("password spray should trigger, got %d", findings[1].Count)
	}
}
