package anssi

import (
	"context"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// runPhaseB executes a detector against `data` and returns the single Finding.
// Phase B detectors all emit at most one Finding (R40 included - one summary).
func runPhaseB(t *testing.T, d audit.Detector, data *audit.DetectorData) *types.Finding {
	t.Helper()
	if data.Now.IsZero() {
		data.Now = time.Now()
	}
	findings := d.Detect(context.Background(), data)
	if len(findings) == 0 {
		return nil
	}
	if len(findings) > 1 {
		t.Fatalf("%s: expected at most 1 finding, got %d", d.ID(), len(findings))
	}
	return &findings[0]
}

// --- M12 ---

func TestM12_DefaultName_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{AdminAccountName: "Administrator"},
	}
	f := runPhaseB(t, NewM12DefaultAdminNotRenamedDetector(), data)
	if f == nil || f.Count != 1 || f.Severity != types.SeverityMedium {
		t.Fatalf("M12 default name should trigger medium finding, got %+v", f)
	}
}

func TestM12_RenamedAccount_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{AdminAccountName: "rootadm-2026"},
	}
	if f := runPhaseB(t, NewM12DefaultAdminNotRenamedDetector(), data); f != nil {
		t.Fatalf("M12 renamed account should not trigger, got %+v", f)
	}
}

// --- R15 functional level ---

func TestR15_LegacyDomain_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{
			FunctionalLevelInt:       4, // Win2008 R2
			ForestFunctionalLevelInt: 4,
			FunctionalLevel:          "Windows2008R2Domain",
			ForestFunctionalLevel:    "Windows2008R2Forest",
			DomainDN:                 "DC=test,DC=local",
		},
	}
	f := runPhaseB(t, NewR15FunctionalLevelDetector(), data)
	if f == nil || f.Severity != types.SeverityHigh {
		t.Fatalf("R15 legacy FL should trigger high, got %+v", f)
	}
	// v3.1.20 - explicit assertion: Reproducibility MUST be populated when
	// R15 fires, so the SaaS UI can display the LDAP query for the auditor.
	if f.Reproducibility == nil || f.Reproducibility.LDAPFilter == "" {
		t.Fatalf("R15 must emit reproducibility.ldapFilter when triggered, got %+v", f.Reproducibility)
	}
}

func TestR15_ModernDomain_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 7, ForestFunctionalLevelInt: 7},
	}
	if f := runPhaseB(t, NewR15FunctionalLevelDetector(), data); f != nil {
		t.Fatalf("R15 modern FL (7) should not trigger, got %+v", f)
	}
}

// R15's own text (p.33) sets its required floor at functional level 6
// (Windows Server 2012 R2), not 7 (2016). The previous threshold (7) was
// stricter than the source and would have flagged a level-6 domain - which
// R15 itself calls sufficient - as non-compliant.
func TestR15_Level6Domain_MeetsANSSIFloor_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{FunctionalLevelInt: 6, ForestFunctionalLevelInt: 6},
	}
	if f := runPhaseB(t, NewR15FunctionalLevelDetector(), data); f != nil {
		t.Fatalf("R15 level 6 (2012R2) meets R15's own required floor and should not trigger, got %+v", f)
	}
}

// --- R19 server core ---
//
// Microsoft's LDAP operatingSystem attribute reports the same string for a
// Server Core install and a Desktop Experience install of the same edition
// - it never actually contains "Server Core" on a real DC. The previous
// implementation treated the (structurally impossible) presence of that
// substring as proof of compliance and its absence as proof of
// non-compliance; the fix instead reports honestly, for every DC
// regardless of its operatingSystem string, that R19+ cannot be confirmed
// via LDAP alone.

func TestR19_AnyDCs_AlwaysReportsCannotConfirmViaLDAP(t *testing.T) {
	data := &audit.DetectorData{
		DomainControllers: []types.Computer{
			{SAMAccountName: "DC01$", OperatingSystem: "Windows Server 2019 Standard"},
			// Even a DC whose OS string happens to literally say "Server
			// Core" must still be reported as unconfirmed - the previous
			// implementation would have excluded this one and only
			// counted DC01, undercounting the set that needs registry
			// confirmation.
			{SAMAccountName: "DC02$", OperatingSystem: "Windows Server 2022 Server Core"},
		},
	}
	f := runPhaseB(t, NewR19ServerCoreNotUsedDetector(), data)
	if f == nil || f.Count != 2 || f.Severity != types.SeverityInfo {
		t.Fatalf("R19 should report an Info-level 'cannot confirm' finding covering all DCs, got %+v", f)
	}
}

func TestR19_NoDCs_NoFinding(t *testing.T) {
	data := &audit.DetectorData{}
	if f := runPhaseB(t, NewR19ServerCoreNotUsedDetector(), data); f != nil {
		t.Fatalf("R19 with no DCs should not trigger, got %+v", f)
	}
}

// --- R40 PSO Tier 0 ---

func TestR40_NoPSOOnDomainAdmins_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: "CN=Domain Admins,CN=Users,DC=test,DC=local"},
		},
		FGPPs: []types.FGPP{}, // no PSO at all
	}
	f := runPhaseB(t, NewR40NoPSOTier0Detector(), data)
	if f == nil || f.Severity != types.SeverityHigh {
		t.Fatalf("R40 no-PSO should trigger high, got %+v", f)
	}
}

func TestR40_PSOCoversTier0_NoFinding(t *testing.T) {
	groupDN := "CN=Domain Admins,CN=Users,DC=test,DC=local"
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Domain Admins", DN: groupDN},
		},
		FGPPs: []types.FGPP{
			{Name: "Tier0-PSO", AppliesTo: []string{groupDN}},
		},
	}
	if f := runPhaseB(t, NewR40NoPSOTier0Detector(), data); f != nil {
		t.Fatalf("R40 covered should not trigger, got %+v", f)
	}
}

// --- R42 trust password ---

func TestR42_OldTrust_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TargetDomain: "old.example.com", PasswordLastSet: time.Now().AddDate(-3, 0, 0)},
		},
		IncludeDetails: true,
	}
	f := runPhaseB(t, NewR42TrustPasswordOldDetector(), data)
	if f == nil || f.Count != 1 {
		t.Fatalf("R42 stale trust should trigger, got %+v", f)
	}
	// v3.1.20 - explicit assertion: Reproducibility MUST be populated when
	// R42 fires (LDAP query is `(objectClass=trustedDomain)`).
	if f.Reproducibility == nil || f.Reproducibility.LDAPFilter == "" {
		t.Fatalf("R42 must emit reproducibility.ldapFilter when triggered, got %+v", f.Reproducibility)
	}
}

func TestR42_RecentTrust_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{{TargetDomain: "recent.example.com", PasswordLastSet: time.Now().AddDate(0, 0, -10)}},
	}
	if f := runPhaseB(t, NewR42TrustPasswordOldDetector(), data); f != nil {
		t.Fatalf("R42 recent trust (10 days) should not trigger, got %+v", f)
	}
}

// R42's own text (p.55): TDO passwords rotate automatically every 30 days,
// and ANSSI recommends a quarterly (~90-day) control to catch ones that
// escape that rule. A TDO stuck for 7 months is clearly "échappant à la
// règle des 30 jours" - the previous 365/730-day thresholds would have let
// it pass through this detector unnoticed for another 5 months.
func TestR42_SevenMonthStaleTrust_TriggersUnderQuarterlyCadence(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{{TargetDomain: "stuck.example.com", PasswordLastSet: time.Now().AddDate(0, -7, 0)}},
	}
	f := runPhaseB(t, NewR42TrustPasswordOldDetector(), data)
	if f == nil || f.Count != 1 {
		t.Fatalf("R42 trust stuck 7 months should trigger under R42's quarterly control cadence, got %+v", f)
	}
}

// v3.1.18 - explicit zero pwdLastSet must produce NO finding (was a false
// positive in v3.1.17 when WhenCreated was used as proxy).
func TestR42_NoPwdLastSet_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{{TargetDomain: "unreadable.example.com"}}, // PasswordLastSet zero
	}
	if f := runPhaseB(t, NewR42TrustPasswordOldDetector(), data); f != nil {
		t.Fatalf("R42 zero pwdLastSet should not trigger, got %+v", f)
	}
}

// --- R43 DC password ---

func TestR43_OldDCPassword_Triggers(t *testing.T) {
	data := &audit.DetectorData{
		DomainControllers: []types.Computer{
			{SAMAccountName: "DC01$", PasswordLastSet: time.Now().AddDate(0, 0, -120)},
		},
	}
	f := runPhaseB(t, NewR43DCPasswordOldDetector(), data)
	if f == nil || f.Severity != types.SeverityHigh {
		t.Fatalf("R43 old DC password should trigger high, got %+v", f)
	}
}

func TestR43_RecentDCPassword_NoFinding(t *testing.T) {
	data := &audit.DetectorData{
		DomainControllers: []types.Computer{
			{SAMAccountName: "DC01$", PasswordLastSet: time.Now().AddDate(0, 0, -10)},
		},
	}
	if f := runPhaseB(t, NewR43DCPasswordOldDetector(), data); f != nil {
		t.Fatalf("R43 recent DC password should not trigger, got %+v", f)
	}
}

// v3.1.21 dedup - TestR69_* removed. The R69 logic was migrated into the
// custom KERBEROASTING_RISK detector (kerberos package), which now emits
// 2 findings : Tier 0 admin with SPN (Critical) + non-Tier 0 service
// account with SPN (High). Coverage is tested in
// internal/audit/detectors/ad/kerberos/kerberoasting-risk_test.go.
