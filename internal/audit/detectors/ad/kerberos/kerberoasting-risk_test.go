package kerberos

import (
	"context"
	"regexp"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// wellKnownSIDMention matches the word "sid" on its own, case-insensitive.
// A plain strings.Contains(desc, "sid") is hollow: "outside Tier 0" (part of
// this same Description's remediation sentence) contains "sid" as a bare
// substring ("outside"[3:6] == "sid"), so that check would stay green even if
// the SID-based recognition wording were deleted entirely. Word boundaries
// make the check actually exercise the sentence it claims to guard.
var wellKnownSIDMention = regexp.MustCompile(`(?i)\bsid\b`)

// tier0CriterionRegression matches any wording that would (re)claim
// AdminCount or AdminSDHolder as a Tier 0 recognition criterion. A
// verification pass proved that a narrower guard (plain
// strings.Contains(lower, "admincount")) lets "admin count = 1" (spaced) and
// "AdminSDHolder" (a different token entirely) both slip through - mutations
// M3 and M5. `admin.?count` covers both the glued and single-separator
// spellings; `adminsdholder` covers the mechanism name directly. Word
// boundaries keep it from firing on unrelated words.
var tier0CriterionRegression = regexp.MustCompile(`(?i)\badmin.?count\b|\badminsdholder\b`)

// TestKerberoastingRiskDescription_DoesNotClaimAdminCountAsTier0Criterion
// locks the Critical Description delivered to the client to the Tier 0
// recognition Detect() actually applies: AdminCount=1 is not a Tier 0
// recognition path in helpers.Tier0Members - the text must not claim
// otherwise, and must keep naming the SID-based recognition that governs it
// instead. No earlier test read this Description string at all, so a stale
// rewording could drift silently; this test reads it directly, not via any
// constant the code itself defines, so a regression back to the old wording
// fails it instead of drifting through unnoticed.
func TestKerberoastingRiskDescription_DoesNotClaimAdminCountAsTier0Criterion(t *testing.T) {
	tier0DN := "CN=alice,OU=Admins,DC=test,DC=local"
	const domainAdminsSID = "S-1-5-21-9998887776-6665554443-3332221110-512"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", ObjectSID: domainAdminsSID, Members: []string{tier0DN}},
		},
		Users: []types.User{
			{DN: tier0DN, SAMAccountName: "alice", ServicePrincipalNames: []string{"http/web01"}},
		},
	}

	findings := NewKerberoastingRiskDetector().Detect(context.Background(), data)
	var critical *types.Finding
	for i := range findings {
		if findings[i].Severity == types.SeverityCritical {
			critical = &findings[i]
		}
	}
	if critical == nil {
		t.Fatalf("expected a Critical Tier 0 finding, got none (findings=%+v)", findings)
	}

	desc := critical.Description
	if tier0CriterionRegression.MatchString(desc) {
		t.Errorf("Critical Description must not name AdminCount or AdminSDHolder as a Tier 0 criterion - got: %q", desc)
	}
	if !wellKnownSIDMention.MatchString(desc) {
		t.Errorf("Critical Description must name SID-based recognition as the Tier 0 criterion - got: %q", desc)
	}
}

// TestKerberoastingRiskDoc_DoesNotClaimAdminCountAsTier0Criterion ties the
// catalog Doc().Description - shown to the client independently of any live
// audit, in docs and in the catalog markdown - to the exact same guard as the
// Detect()-time Description above. The verifier's mutation M5 proved these
// two texts can drift apart silently: reverting Doc() (and the catalog) to
// the old "AdminSDHolder" wording while leaving Detect()'s Description fixed
// left every prior test green, because no test read Doc() at all.
func TestKerberoastingRiskDoc_DoesNotClaimAdminCountAsTier0Criterion(t *testing.T) {
	desc := NewKerberoastingRiskDetector().Doc().Description
	if tier0CriterionRegression.MatchString(desc) {
		t.Errorf("Doc().Description must not name AdminCount or AdminSDHolder as a Tier 0 criterion - got: %q", desc)
	}
	if !wellKnownSIDMention.MatchString(desc) {
		t.Errorf("Doc().Description must name SID-based recognition as the Tier 0 criterion - got: %q", desc)
	}
}

// TestKerberoasting_Tier0Split verifies that KERBEROASTING_RISK partitions
// Kerberoastable accounts by Tier 0 membership (recursive group expansion +
// SID-based seed resolution - not AdminCount=1 anymore) + tier0_groups.yaml
// customer overrides) and emits a separate Critical finding for Tier 0
// hits - matching the scope of the deleted ANSSI_R69_TIER0_SPN_EXPOSED
// detector. v3.1.21 migration coverage.
//
// Groups here carry a literal Domain Admins RID (-512) distinct from any
// constant in tier0.go, matching the seed's SID-based matching:
// sAMAccountName alone no longer makes a group Tier 0.
func TestKerberoasting_Tier0Split(t *testing.T) {
	tier0DN := "CN=alice,OU=Admins,DC=test,DC=local"
	svcDN := "CN=svc,OU=Services,DC=test,DC=local"
	const domainAdminsSID = "S-1-5-21-4004336348-4177238915-4682003330-512"

	cases := []struct {
		name            string
		data            *audit.DetectorData
		wantTier0Count  int
		wantOthersCount int
		wantTier0Sev    types.Severity
		wantOthersSev   types.Severity
	}{
		{
			name: "Tier 0 admin with SPN → 1 Critical finding only",
			data: &audit.DetectorData{
				Groups: []types.Group{
					{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", ObjectSID: domainAdminsSID, Members: []string{tier0DN}},
				},
				Users: []types.User{
					{DN: tier0DN, SAMAccountName: "alice", ServicePrincipalNames: []string{"http/web01"}},
				},
				IncludeDetails: true,
			},
			wantTier0Count: 1,
			wantTier0Sev:   types.SeverityCritical,
		},
		{
			name: "Service account with SPN (non-Tier 0) → 1 High finding only",
			data: &audit.DetectorData{
				Groups: []types.Group{
					{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", ObjectSID: domainAdminsSID, Members: nil},
				},
				Users: []types.User{
					{DN: svcDN, SAMAccountName: "svc", ServicePrincipalNames: []string{"http/web01"}},
				},
			},
			wantOthersCount: 1,
			wantOthersSev:   types.SeverityHigh,
		},
		{
			name: "Both Tier 0 and non-Tier 0 → 2 distinct findings",
			data: &audit.DetectorData{
				Groups: []types.Group{
					{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", ObjectSID: domainAdminsSID, Members: []string{tier0DN}},
				},
				Users: []types.User{
					{DN: tier0DN, SAMAccountName: "alice", ServicePrincipalNames: []string{"http/web01"}},
					{DN: svcDN, SAMAccountName: "svc", ServicePrincipalNames: []string{"mssql/db01"}},
				},
			},
			wantTier0Count:  1,
			wantTier0Sev:    types.SeverityCritical,
			wantOthersCount: 1,
			wantOthersSev:   types.SeverityHigh,
		},
		{
			name: "No Kerberoastable accounts → no findings",
			data: &audit.DetectorData{
				Users: []types.User{
					{DN: svcDN, SAMAccountName: "svc"}, // no SPN
				},
			},
		},
		{
			// Coverage gap from an earlier validation pass: no existing case
			// built a Disabled+SPN user, so the exclusion at Detect()'s
			// `user.Disabled || len(...) == 0` line was never exercised by
			// this table. Closed here. That exclusion was measured CORRECT
			// against a real KDC (it refuses to issue a TGS for a disabled
			// account's own SPN) - a Tier 0 admin with SPN who is also
			// disabled must still produce zero findings.
			name: "Disabled Tier 0 admin with SPN → no findings at all",
			data: &audit.DetectorData{
				Groups: []types.Group{
					{SAMAccountName: "Domain Admins", DN: "CN=DA,DC=test,DC=local", ObjectSID: domainAdminsSID, Members: []string{tier0DN}},
				},
				Users: []types.User{
					{DN: tier0DN, SAMAccountName: "alice", ServicePrincipalNames: []string{"http/web01"}, Disabled: true},
				},
			},
		},
		{
			// D4 at the DETECTOR level, not just the helper level. The
			// helper-level test (TestTier0Members_AdminCountAloneIsNotTier0,
			// helpers/tier0_test.go) proves Tier0Members excludes an
			// AdminCount=1 orphan - but it calls the helper directly, never
			// this package's Detect(). This case reproduces the exact real
			// shape measured on the reference lab forest: a user with
			// AdminCount=1, zero group membership (no Groups at all in the
			// fixture - not even an empty Members list), carrying a SPN. It
			// must land in the High/non-Tier-0 bucket, never Critical.
			name: "AdminCount=1 orphan with SPN, no group membership → 1 High finding, never Critical",
			data: &audit.DetectorData{
				Users: []types.User{
					{DN: svcDN, SAMAccountName: "svc", ServicePrincipalNames: []string{"http/web01"}, AdminCount: true},
				},
			},
			wantOthersCount: 1,
			wantOthersSev:   types.SeverityHigh,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewKerberoastingRiskDetector()
			findings := d.Detect(context.Background(), tc.data)

			var tier0F, othersF *types.Finding
			for i := range findings {
				if findings[i].Severity == types.SeverityCritical {
					tier0F = &findings[i]
				} else {
					othersF = &findings[i]
				}
			}

			if tc.wantTier0Count == 0 && tier0F != nil {
				t.Errorf("expected no Tier 0 finding, got %+v", tier0F)
			}
			if tc.wantTier0Count > 0 {
				if tier0F == nil {
					t.Errorf("expected Tier 0 finding (count=%d, sev=%s), got nil", tc.wantTier0Count, tc.wantTier0Sev)
				} else if tier0F.Count != tc.wantTier0Count || tier0F.Severity != tc.wantTier0Sev {
					t.Errorf("Tier 0 finding mismatch: got count=%d sev=%s, want count=%d sev=%s",
						tier0F.Count, tier0F.Severity, tc.wantTier0Count, tc.wantTier0Sev)
				}
			}
			if tc.wantOthersCount == 0 && othersF != nil {
				t.Errorf("expected no non-Tier-0 finding, got %+v", othersF)
			}
			if tc.wantOthersCount > 0 {
				if othersF == nil {
					t.Errorf("expected non-Tier-0 finding (count=%d, sev=%s), got nil", tc.wantOthersCount, tc.wantOthersSev)
				} else if othersF.Count != tc.wantOthersCount || othersF.Severity != tc.wantOthersSev {
					t.Errorf("non-Tier-0 finding mismatch: got count=%d sev=%s, want count=%d sev=%s",
						othersF.Count, othersF.Severity, tc.wantOthersCount, tc.wantOthersSev)
				}
			}
		})
	}
}
