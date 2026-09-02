package types

import "testing"

// T_057 / B_165 — on the DC01 reference, 1109 of 1359 critical/high account
// entities are disabled accounts that cannot authenticate today, yet the
// score was computed upstream of annotateDisabledAccounts (engine.go, before
// ConvertToTSFormat ever runs) and weighed every one of them exactly as
// heavily as a live account. This file covers the fix on the model of
// disabled_accounts_test.go: the score now excludes the disabled share of
// each finding's account entities, while the DISPLAYED finding — Count,
// Severity, AffectedEntities — stays exactly what result.Findings said.

// scoreOf is a small helper: build a minimal AuditResult around the given
// findings and entity totals, run it through ConvertToTSFormat, and return
// the resulting risk score/rating.
func scoreOf(t *testing.T, findings []Finding, users, computers, groups int) (float64, string) {
	t.Helper()
	result := &AuditResult{
		Findings: findings,
		Statistics: &AuditStatistics{
			UsersScanned:     users,
			ComputersScanned: computers,
			GroupsScanned:    groups,
		},
	}
	resp := ConvertToTSFormat(result, "ad", "ldaps://dc01", "DC=example,DC=com", true)
	risk := resp.Audit.Summary.Risk
	return risk.Score, risk.Rating
}

// TestScore_AllDisabledFindingContributesNothing is the core acceptance
// case: ORPHANED_SID_DANGEROUS_ACE on DC01 is Count=293, all 293 target
// accounts disabled (T_042/T_057 — the orphan SID's grant lands entirely on
// dormant accounts). A score computed with it must equal one computed
// without it: the finding contributes zero, exactly as an absent finding
// would, because none of its accounts can authenticate right now.
func TestScore_AllDisabledFindingContributesNothing(t *testing.T) {
	entities := make([]AffectedEntity, 293)
	for i := range entities {
		entities[i] = AffectedEntity{Type: "user", SAMAccountName: "ghost", Enabled: false}
	}
	allDisabled := []Finding{{
		Type: "ORPHANED_SID_DANGEROUS_ACE", Severity: SeverityHigh, Category: "permissions",
		Count: 293, AffectedEntities: entities,
	}}

	withFinding, ratingWith := scoreOf(t, allDisabled, 1660, 200, 150)
	withoutFinding, ratingWithout := scoreOf(t, nil, 1660, 200, 150)

	if withFinding != withoutFinding {
		t.Errorf("score with an all-disabled finding = %v, want %v (same as no finding at all — none of its accounts can authenticate)",
			withFinding, withoutFinding)
	}
	if ratingWith != ratingWithout {
		t.Errorf("rating = %q, want %q", ratingWith, ratingWithout)
	}
}

// TestScore_MixedFindingCountsOnlyTheEnabledShare covers the partial case:
// UNCONSTRAINED_DELEGATION-shaped finding, 20 accounts, 18 disabled — the
// score must move as if Count were 2 (the enabled share), not 20.
func TestScore_MixedFindingCountsOnlyTheEnabledShare(t *testing.T) {
	var entities []AffectedEntity
	for i := 0; i < 18; i++ {
		entities = append(entities, AffectedEntity{Type: "user", SAMAccountName: "ghost", Enabled: false})
	}
	entities = append(entities,
		AffectedEntity{Type: "user", SAMAccountName: "live1", Enabled: true},
		AffectedEntity{Type: "user", SAMAccountName: "live2", Enabled: true},
	)
	mixed := []Finding{{
		Type: "UNCONSTRAINED_DELEGATION", Severity: SeverityCritical, Category: "accounts",
		Count: 20, AffectedEntities: entities,
	}}
	twoOnly := []Finding{{
		Type: "UNCONSTRAINED_DELEGATION", Severity: SeverityCritical, Category: "accounts",
		Count: 2, AffectedEntities: entities[18:],
	}}

	gotMixed, _ := scoreOf(t, mixed, 1660, 200, 150)
	gotTwoOnly, _ := scoreOf(t, twoOnly, 1660, 200, 150)

	if gotMixed != gotTwoOnly {
		t.Errorf("score for 20-accounts/18-disabled = %v, want %v (must score identically to a 2-account finding)",
			gotMixed, gotTwoOnly)
	}
}

// TestScore_NoDisabledAccountsIsUnaffected is the non-regression proof: a
// finding with zero disabled accounts must score EXACTLY as CalculateScore
// already did before this ticket — same Count, same formula, no new
// behavior introduced for the common case.
func TestScore_NoDisabledAccountsIsUnaffected(t *testing.T) {
	allEnabled := []Finding{{
		Type: "ASREP_ROASTING_RISK", Severity: SeverityCritical, Category: "accounts",
		Count: 5,
		AffectedEntities: []AffectedEntity{
			{Type: "user", Enabled: true}, {Type: "user", Enabled: true}, {Type: "user", Enabled: true},
			{Type: "user", Enabled: true}, {Type: "user", Enabled: true},
		},
	}}

	got, _ := scoreOf(t, allEnabled, 1660, 200, 150)
	want, _ := CalculateScore(allEnabled, 1660, 200, 150)

	if got != want {
		t.Errorf("score with no disabled accounts = %v, want %v (must match CalculateScore unmodified)", got, want)
	}
}

// TestScore_FindingWithNoAccountEntitiesIsUnaffected covers findings whose
// AffectedEntities carry no user/computer type at all (ACL entries, GPOs,
// OUs — annotateDisabledAccounts already ignores these): their full Count
// must still weigh on the score, unchanged.
func TestScore_FindingWithNoAccountEntitiesIsUnaffected(t *testing.T) {
	aclFinding := []Finding{{
		Type: "ACL_WRITEDACL", Severity: SeverityHigh, Category: "permissions",
		Count: 6,
		AffectedEntities: []AffectedEntity{
			{Type: "aclEntry", Right: "WriteDACL"},
			{Type: "ou", DN: "OU=IT,DC=example,DC=com"},
		},
	}}

	got, _ := scoreOf(t, aclFinding, 1660, 200, 150)
	want, _ := CalculateScore(aclFinding, 1660, 200, 150)

	if got != want {
		t.Errorf("score for a non-account finding = %v, want %v (must match CalculateScore unmodified)", got, want)
	}
}

// TestScore_DisplayedFindingIsUntouched is the "nothing disappears, nothing
// is downgraded" guarantee (acceptance criteria): the score changes, but the
// finding a reader sees — Count, Severity, AffectedEntities — is exactly
// result.Findings, byte for byte.
func TestScore_DisplayedFindingIsUntouched(t *testing.T) {
	entities := make([]AffectedEntity, 293)
	for i := range entities {
		entities[i] = AffectedEntity{Type: "user", SAMAccountName: "ghost", Enabled: false}
	}
	orig := Finding{
		Type: "ORPHANED_SID_DANGEROUS_ACE", Severity: SeverityHigh, Category: "permissions",
		Count: 293, AffectedEntities: entities,
	}

	result := &AuditResult{
		Findings:   []Finding{orig},
		Statistics: &AuditStatistics{UsersScanned: 1660, ComputersScanned: 200, GroupsScanned: 150},
	}
	resp := ConvertToTSFormat(result, "ad", "ldaps://dc01", "DC=example,DC=com", true)

	var got *Finding
	for _, f := range resp.Audit.Permissions.Findings {
		if f.Type == "ORPHANED_SID_DANGEROUS_ACE" {
			fc := f
			got = &fc
		}
	}
	if got == nil {
		t.Fatalf("ORPHANED_SID_DANGEROUS_ACE disappeared from the report")
	}
	if got.Count != 293 {
		t.Errorf("displayed Count = %d, want 293 (unchanged — the score adjustment must never touch the displayed finding)", got.Count)
	}
	if got.Severity != SeverityHigh {
		t.Errorf("displayed Severity = %q, want high (must not be downgraded)", got.Severity)
	}
	if len(got.AffectedEntities) != 293 {
		t.Errorf("displayed AffectedEntities = %d, want 293", len(got.AffectedEntities))
	}
	// Also still fully marked, per the pre-existing T_031 arbitration.
	if got.Details["disabledAccounts"] != 293 || got.Details["affectedAccounts"] != 293 {
		t.Errorf("details = %v, want 293 disabled of 293", got.Details)
	}
}

// TestAnnotateDisabledAccountsReturnsCounts locks the new return values used
// by the score recomputation (T_057) — the pre-existing marking behavior
// (Details) is already covered by TestDisabledAccountsAreMarkedNotDropped.
func TestAnnotateDisabledAccountsReturnsCounts(t *testing.T) {
	f := Finding{
		AffectedEntities: []AffectedEntity{
			{Type: "user", Enabled: false},
			{Type: "user", Enabled: true},
			{Type: "computer", Enabled: false},
			{Type: "ou", DN: "OU=IT,DC=example,DC=com"}, // not an account type — ignored
		},
	}
	disabled, accounts := annotateDisabledAccounts(&f)
	if disabled != 2 || accounts != 3 {
		t.Errorf("annotateDisabledAccounts = (%d, %d), want (2, 3)", disabled, accounts)
	}
}
