package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestAnonymizeSignInIPs(t *testing.T) {
	logs := []types.SignInLog{
		{IPAddress: "192.168.1.42"},
		{IPAddress: "10.0.255.7"},
		{IPAddress: "2001:db8::1"}, // IPv6 — unchanged
		{IPAddress: ""},            // empty — unchanged
		{IPAddress: "garbage"},     // unparseable — unchanged
	}
	AnonymizeSignInIPs(logs)
	cases := []struct {
		idx  int
		want string
	}{
		{0, "192.168.1.0"},
		{1, "10.0.255.0"},
		{2, "2001:db8::1"},
		{3, ""},
		{4, "garbage"},
	}
	for _, tc := range cases {
		if logs[tc.idx].IPAddress != tc.want {
			t.Errorf("logs[%d].IPAddress = %q, want %q", tc.idx, logs[tc.idx].IPAddress, tc.want)
		}
	}
}

func newSignIn(opts ...func(*types.SignInLog)) types.SignInLog {
	s := types.SignInLog{
		ID:                     "evt",
		CreatedDateTime:        time.Now(),
		Status:                 &types.SignInStatus{ErrorCode: 0},
		ClientAppUsed:          "Browser",
		AuthenticationProtocol: "oAuth2",
		Location:               &types.SignInLocation{CountryOrRegion: "FR"},
		SignInEventTypes:       []string{"interactiveUser"},
	}
	for _, f := range opts {
		f(&s)
	}
	return s
}

func TestAggregateSignInLogs_BasicCounters(t *testing.T) {
	logs := []types.SignInLog{
		newSignIn(),
		newSignIn(func(s *types.SignInLog) { s.Status = &types.SignInStatus{ErrorCode: 50140} }), // failure
		newSignIn(func(s *types.SignInLog) {
			s.AuthenticationDetails = []types.SignInAuthDetail{
				{Succeeded: true, AuthenticationMethod: "Password"},
				{Succeeded: true, AuthenticationMethod: "Microsoft Authenticator app verification code"},
			}
		}),
		newSignIn(func(s *types.SignInLog) { s.ClientAppUsed = "Other clients" }), // legacy
		newSignIn(func(s *types.SignInLog) { s.AuthenticationProtocol = "deviceCode" }),
		newSignIn(func(s *types.SignInLog) { s.CrossTenantAccessType = "b2bCollaboration"; s.UserType = "Guest" }),
	}
	agg := AggregateSignInLogs(logs)

	if agg.Total != 6 {
		t.Errorf("Total = %d, want 6", agg.Total)
	}
	if agg.SuccessCount != 5 {
		t.Errorf("SuccessCount = %d, want 5", agg.SuccessCount)
	}
	if agg.FailureCount != 1 {
		t.Errorf("FailureCount = %d, want 1", agg.FailureCount)
	}
	if agg.MFACount != 1 {
		t.Errorf("MFACount = %d, want 1", agg.MFACount)
	}
	if agg.LegacyAuthCount != 1 {
		t.Errorf("LegacyAuthCount = %d, want 1", agg.LegacyAuthCount)
	}
	if agg.DeviceCodeCount != 1 {
		t.Errorf("DeviceCodeCount = %d, want 1", agg.DeviceCodeCount)
	}
	if agg.CrossTenantCount != 1 {
		t.Errorf("CrossTenantCount = %d, want 1", agg.CrossTenantCount)
	}
	if agg.GuestCount != 1 {
		t.Errorf("GuestCount = %d, want 1", agg.GuestCount)
	}
}

func TestAggregateSignInLogs_BucketsSumToTotal(t *testing.T) {
	logs := []types.SignInLog{
		newSignIn(func(s *types.SignInLog) { s.UserPrincipalName = "alice@x" }),
		newSignIn(func(s *types.SignInLog) { s.UserPrincipalName = "alice@x" }),
		newSignIn(func(s *types.SignInLog) { s.UserPrincipalName = "bob@x" }),
	}
	agg := AggregateSignInLogs(logs)
	sum := 0
	for _, b := range agg.ByClientApp {
		sum += b.Count
	}
	if sum != agg.Total {
		t.Errorf("ByClientApp sum = %d, want Total %d", sum, agg.Total)
	}
	// Top users ordering: alice (2) > bob (1)
	if len(agg.TopUsersByVolume) != 2 {
		t.Fatalf("TopUsersByVolume len = %d, want 2", len(agg.TopUsersByVolume))
	}
	if agg.TopUsersByVolume[0].UserPrincipalName != "alice@x" {
		t.Errorf("Top1 = %q, want alice@x", agg.TopUsersByVolume[0].UserPrincipalName)
	}
}

func TestAggregateSignInLogs_RiskySubset(t *testing.T) {
	logs := []types.SignInLog{
		newSignIn(),
		newSignIn(func(s *types.SignInLog) { s.RiskState = "atRisk"; s.RiskLevelAggregated = "high" }),
		newSignIn(func(s *types.SignInLog) { s.RiskState = "none" }), // not risky
		newSignIn(func(s *types.SignInLog) { s.RiskState = "confirmedCompromised" }),
	}
	agg := AggregateSignInLogs(logs)
	if len(agg.RiskySignIns) != 2 {
		t.Errorf("RiskySignIns len = %d, want 2 (atRisk + confirmedCompromised, not 'none')", len(agg.RiskySignIns))
	}
}

func TestAggregateSignInLogs_SPRollupCapsLastEvents(t *testing.T) {
	var logs []types.SignInLog
	for i := 0; i < 150; i++ {
		logs = append(logs, newSignIn(func(s *types.SignInLog) {
			s.SignInEventTypes = []string{"servicePrincipal"}
			s.AppID = "sp-1"
			s.AppDisplayName = "sp-1"
		}))
	}
	agg := AggregateSignInLogs(logs)
	if len(agg.TopServicePrincipals) != 1 {
		t.Fatalf("TopServicePrincipals len = %d, want 1", len(agg.TopServicePrincipals))
	}
	sp := agg.TopServicePrincipals[0]
	if sp.Count != 150 {
		t.Errorf("Count = %d, want 150", sp.Count)
	}
	if len(sp.LastEvents) != 100 {
		t.Errorf("LastEvents len = %d, want 100 (sliding window cap)", len(sp.LastEvents))
	}
}

// TestDecodeGraphBetaFixture is a canary test: it decodes a real Graph
// /beta/auditLogs/signIns response captured against the test tenant
// (anonymised) and asserts the critical fields are still mapped correctly.
//
// Microsoft beta endpoints have no SLA — fields can be renamed, removed, or
// re-typed without notice. Failing this test is the early-warning signal
// that we need to rev the SignInLog struct (e.g. signInType → signInEventTypes
// drift we hit during initial v3.1.30 validation).
//
// Anonymisation: UUIDs scrambled, UPNs replaced with example.com, IPs
// replaced with TEST-NET-1 (RFC 5737), display names neutralised.
func TestDecodeGraphBetaFixture(t *testing.T) {
	const fixture = `{
		"id": "00000000-0000-0000-0000-000000000001",
		"createdDateTime": "2026-05-03T10:00:00Z",
		"userId": "11111111-1111-1111-1111-111111111111",
		"userPrincipalName": "alice@example.com",
		"userDisplayName": "Alice Example",
		"userType": "member",
		"appId": "22222222-2222-2222-2222-222222222222",
		"appDisplayName": "Microsoft Office",
		"clientAppUsed": "Browser",
		"conditionalAccessStatus": "success",
		"appliedConditionalAccessPolicies": [
			{
				"id": "33333333-3333-3333-3333-333333333333",
				"displayName": "Require MFA for admins",
				"enforcedGrantControls": ["Mfa"],
				"result": "success"
			}
		],
		"authenticationProtocol": "oAuth2",
		"authenticationDetails": [
			{
				"authenticationStepDateTime": "2026-05-03T10:00:00Z",
				"authenticationMethod": "Password",
				"succeeded": true
			},
			{
				"authenticationStepDateTime": "2026-05-03T10:00:05Z",
				"authenticationMethod": "Microsoft Authenticator app verification code",
				"succeeded": true
			}
		],
		"riskState": "atRisk",
		"riskLevelAggregated": "high",
		"riskLevelDuringSignIn": "high",
		"riskEventTypes_v2": ["unfamiliarFeatures"],
		"tokenIssuerType": "AzureAD",
		"crossTenantAccessType": "none",
		"signInIdentifier": "alice@example.com",
		"location": {"city": "Paris", "state": "Paris", "countryOrRegion": "FR"},
		"ipAddress": "192.0.2.42",
		"deviceDetail": {
			"deviceId": "44444444-4444-4444-4444-444444444444",
			"operatingSystem": "Windows 11",
			"browser": "Edge",
			"isCompliant": true,
			"isManaged": true
		},
		"status": {"errorCode": 0, "failureReason": "Other."},
		"correlationId": "55555555-5555-5555-5555-555555555555",
		"sessionLifetimePolicies": [
			{"expirationType": "primaryAndSecondaryRefreshTokenUpdate", "detail": "tenantToken"}
		],
		"incomingTokenType": "primaryRefreshToken",
		"signInEventTypes": ["interactiveUser"]
	}`
	var ev types.SignInLog
	if err := json.Unmarshal([]byte(fixture), &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Critical-field assertions — drift here = SaaS analyzer breaks.
	if ev.ID != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("ID = %q", ev.ID)
	}
	if ev.CreatedDateTime.IsZero() {
		t.Errorf("CreatedDateTime not parsed")
	}
	if ev.UserPrincipalName != "alice@example.com" {
		t.Errorf("UserPrincipalName = %q", ev.UserPrincipalName)
	}
	if ev.AppDisplayName != "Microsoft Office" {
		t.Errorf("AppDisplayName = %q", ev.AppDisplayName)
	}
	if len(ev.AppliedConditionalAccessPolicies) != 1 {
		t.Fatalf("AppliedConditionalAccessPolicies len = %d", len(ev.AppliedConditionalAccessPolicies))
	}
	ca := ev.AppliedConditionalAccessPolicies[0]
	if ca.ID != "33333333-3333-3333-3333-333333333333" || ca.Result != "success" {
		t.Errorf("CA[0] mismatch: %+v", ca)
	}
	if len(ev.AuthenticationDetails) != 2 || !ev.AuthenticationDetails[1].Succeeded {
		t.Errorf("AuthenticationDetails len/succeeded mismatch: %+v", ev.AuthenticationDetails)
	}
	if ev.RiskState != "atRisk" || ev.RiskLevelAggregated != "high" {
		t.Errorf("Risk fields mismatch: state=%q level=%q", ev.RiskState, ev.RiskLevelAggregated)
	}
	if len(ev.RiskEventTypesV2) != 1 || ev.RiskEventTypesV2[0] != "unfamiliarFeatures" {
		t.Errorf("RiskEventTypesV2 mismatch: %v", ev.RiskEventTypesV2)
	}
	if ev.IncomingTokenType != "primaryRefreshToken" {
		t.Errorf("IncomingTokenType = %q", ev.IncomingTokenType)
	}
	if len(ev.SignInEventTypes) != 1 || ev.SignInEventTypes[0] != "interactiveUser" {
		t.Errorf("SignInEventTypes = %v (drift signal — Graph schema renamed?)", ev.SignInEventTypes)
	}
	if ev.Location == nil || ev.Location.CountryOrRegion != "FR" {
		t.Errorf("Location mismatch: %+v", ev.Location)
	}
	if ev.DeviceDetail == nil || ev.DeviceDetail.IsCompliant == nil || !*ev.DeviceDetail.IsCompliant {
		t.Errorf("DeviceDetail.IsCompliant mismatch: %+v", ev.DeviceDetail)
	}
	if ev.Status == nil || ev.Status.ErrorCode != 0 {
		t.Errorf("Status mismatch: %+v", ev.Status)
	}
	if len(ev.SessionLifetimePolicies) != 1 {
		t.Errorf("SessionLifetimePolicies len = %d", len(ev.SessionLifetimePolicies))
	}
}

func TestAggregateSignInLogs_EmptyInput(t *testing.T) {
	agg := AggregateSignInLogs(nil)
	if agg == nil || agg.Total != 0 {
		t.Errorf("nil input should produce zero-valued aggregate, got %#v", agg)
	}
}
