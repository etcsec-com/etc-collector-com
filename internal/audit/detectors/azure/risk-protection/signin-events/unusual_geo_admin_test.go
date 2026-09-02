package signinevents

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const geoAdminUPN = "admin@example.com"
const geoAdminID = "admin-1"

var geoAdminAssignments = []types.RoleAssignment{
	{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: geoAdminID, UserPrincipalName: geoAdminUPN, PrincipalType: "User"},
}

// adminSignIn builds a successful admin sign-in from `country` at the given
// offset from testBaseTime (negative = older).
func adminSignIn(country string, offset time.Duration, opts ...func(*types.SignInLog)) types.SignInLog {
	ev := types.SignInLog{
		ID:                country + "-" + offset.String(),
		CreatedDateTime:   testBaseTime.Add(offset),
		UserID:            geoAdminID,
		UserPrincipalName: geoAdminUPN,
		UserDisplayName:   "Admin",
		IPAddress:         "203.0.113.9",
		Location:          &types.SignInLocation{City: "Paris", CountryOrRegion: country},
		Status:            &types.SignInStatus{ErrorCode: 0},
	}
	for _, opt := range opts {
		opt(&ev)
	}
	return ev
}

// adminHistory lays down `days` days of daily sign-ins from `country`.
func adminHistory(country string, days int) []types.SignInLog {
	var logs []types.SignInLog
	for day := 0; day < days; day++ {
		logs = append(logs, adminSignIn(country, -time.Duration(days+1-day)*24*time.Hour))
	}
	return logs
}

func geoData(logs []types.SignInLog, assignments []types.RoleAssignment) *audit.DetectorData {
	return &audit.DetectorData{
		AzureSignInLogs:      logs,
		AzureRoleAssignments: assignments,
		IncludeDetails:       true,
	}
}

func TestUnusualGeoAdminDetector(t *testing.T) {
	det := NewUnusualGeoAdminDetector()

	cases := []struct {
		name      string
		data      *audit.DetectorData
		wantCount int
		reason    string
	}{
		{
			name:      "no sign-in logs at all",
			data:      geoData(nil, geoAdminAssignments),
			wantCount: 0,
			reason:    "no data must never be a finding",
		},
		{
			name:      "admin signs in from a new country",
			data:      geoData(append(adminHistory("FR", 10), adminSignIn("RU", 0)), geoAdminAssignments),
			wantCount: 1,
			reason:    "10 days of FR then a successful RU sign-in is the case this detector exists for",
		},
		{
			name:      "same country as always",
			data:      geoData(append(adminHistory("FR", 10), adminSignIn("FR", 0)), geoAdminAssignments),
			wantCount: 0,
			reason:    "no change of geography",
		},
		{
			name:      "country already known from the baseline",
			data:      geoData(append(append(adminHistory("FR", 10), adminSignIn("BE", -3*24*time.Hour)), adminSignIn("BE", 0)), geoAdminAssignments),
			wantCount: 0,
			reason:    "BE is part of this admin's usual set",
		},
		{
			name:      "no role assignments — no admins to judge",
			data:      geoData(append(adminHistory("FR", 10), adminSignIn("RU", 0)), nil),
			wantCount: 0,
			reason:    "without role assignments every user would look like an admin",
		},
		{
			name: "non-privileged user travelling is not our business",
			data: geoData(append(adminHistory("FR", 10), adminSignIn("RU", 0)), []types.RoleAssignment{
				{RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "someone-else", UserPrincipalName: "other@example.com", PrincipalType: "User"},
			}),
			wantCount: 0,
			reason:    "only privileged accounts are in scope",
		},
		{
			name:      "baseline too short to establish a usual country",
			data:      geoData(append(adminHistory("FR", 3), adminSignIn("RU", 0)), geoAdminAssignments),
			wantCount: 0,
			reason:    "a 3-day window cannot establish where this admin usually signs in",
		},
		{
			name: "new admin with too few baseline sign-ins",
			data: geoData(append(
				// Long window (another admin keeps it open) but this admin has
				// only 2 baseline sign-ins of their own.
				append(adminHistory("FR", 2), otherAdminHistory(12)...),
				adminSignIn("RU", 0),
			), append(geoAdminAssignments, types.RoleAssignment{
				RoleID: types.AzureRoleGlobalAdmin, PrincipalID: "admin-2", UserPrincipalName: "second@example.com", PrincipalType: "User",
			})),
			wantCount: 0,
			reason:    "2 prior sign-ins is not an established pattern",
		},
		{
			name: "failed sign-in from a new country is a different signal",
			data: geoData(append(adminHistory("FR", 10), adminSignIn("RU", 0, func(ev *types.SignInLog) {
				ev.Status = &types.SignInStatus{ErrorCode: 50126}
			})), geoAdminAssignments),
			wantCount: 0,
			reason:    "failures are covered by the burst detectors and would inflate this one",
		},
		{
			name: "sign-in with no resolved country cannot be unusual",
			data: geoData(append(adminHistory("FR", 10), adminSignIn("", 0, func(ev *types.SignInLog) {
				ev.Location = nil
			})), geoAdminAssignments),
			wantCount: 0,
			reason:    "missing geolocation is absence of data, not a new country",
		},
		{
			name: "baseline without any resolved country gives nothing to compare",
			data: geoData(append(func() []types.SignInLog {
				logs := adminHistory("FR", 10)
				for i := range logs {
					logs[i].Location = nil
				}
				return logs
			}(), adminSignIn("RU", 0)), geoAdminAssignments),
			wantCount: 0,
			reason:    "an empty known-set must not make every country unusual",
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
			if findings[0].Severity != types.SeverityHigh {
				t.Errorf("Severity = %s, want high", findings[0].Severity)
			}
			if findings[0].Type != RISK_UNUSUAL_GEO_ADMIN {
				t.Errorf("Type = %s, want %s", findings[0].Type, RISK_UNUSUAL_GEO_ADMIN)
			}
		})
	}
}

// otherAdminHistory keeps the collected window wide without contributing to the
// admin under test.
func otherAdminHistory(days int) []types.SignInLog {
	var logs []types.SignInLog
	for day := 0; day < days; day++ {
		ev := adminSignIn("FR", -time.Duration(days+1-day)*24*time.Hour)
		ev.UserID = "admin-2"
		ev.UserPrincipalName = "second@example.com"
		logs = append(logs, ev)
	}
	return logs
}

func TestUnusualGeoAdminDetector_Evidence(t *testing.T) {
	data := geoData(append(adminHistory("FR", 10), adminSignIn("RU", 0)), geoAdminAssignments)
	findings := NewUnusualGeoAdminDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 || len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 affected entity, got count=%d entities=%d", findings[0].Count, len(findings[0].AffectedEntities))
	}
	ctx := findings[0].AffectedEntities[0].Azure.SignInRiskContext

	newCountries, _ := ctx["newCountries"].([]string)
	if len(newCountries) != 1 || newCountries[0] != "RU" {
		t.Errorf("newCountries = %v, want [RU]", ctx["newCountries"])
	}
	knownCountries, _ := ctx["knownCountries"].([]string)
	if len(knownCountries) != 1 || knownCountries[0] != "FR" {
		t.Errorf("knownCountries = %v, want [FR]", ctx["knownCountries"])
	}
	if ctx["baselineSignIns"] != 10 {
		t.Errorf("baselineSignIns = %v, want 10", ctx["baselineSignIns"])
	}
}

func TestUnusualGeoAdminDetector_TruncatedStream(t *testing.T) {
	data := geoData(append(adminHistory("FR", 10), adminSignIn("RU", 0)), geoAdminAssignments)
	data.AzureSignInLogsTruncated = true
	data.AzureSignInLogsEventsCollected = 500000

	findings := NewUnusualGeoAdminDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Severity != types.SeverityInfo {
		t.Errorf("Severity = %s, want info — a truncated baseline cannot support a verdict", f.Severity)
	}
	if f.Count == 0 {
		t.Error("Count 0 is filtered out by the engine — the skipped analysis would read as a clean result")
	}
	if got := f.Details["analysisSkipped"]; got != "signInLogsTruncated" {
		t.Errorf("Details[analysisSkipped] = %v, want signInLogsTruncated", got)
	}
}
