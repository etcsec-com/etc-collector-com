package types

import "testing"

// T_031 / B_031 — the report used to announce 0 disabled accounts on a domain
// where 519 of 546 are disabled, and 176 critical entities across 11 detectors
// pointed at accounts that cannot authenticate.

// TestObjectsSummaryReportsTheRealDisabledSplit covers the counter: the summary
// must carry the collected split, never a hard-coded 0.
func TestObjectsSummaryReportsTheRealDisabledSplit(t *testing.T) {
	// The live DC01 numbers.
	const (
		total    = 546
		disabled = 519
		enabled  = total - disabled
	)

	result := &AuditResult{
		Findings: []Finding{},
		Statistics: &AuditStatistics{
			UsersScanned:  total,
			UsersDisabled: disabled,
			UsersEnabled:  enabled,
			GroupsScanned: 154,
		},
	}

	for _, provider := range []string{"ad", "azure"} {
		resp := ConvertToTSFormat(result, provider, "ldaps://dc01", "DC=example,DC=com", true)
		objects := resp.Audit.Summary.Objects

		if objects.UsersDisabled != disabled {
			t.Errorf("%s: users_disabled = %d, want %d", provider, objects.UsersDisabled, disabled)
		}
		if objects.UsersEnabled != enabled {
			t.Errorf("%s: users_enabled = %d, want %d", provider, objects.UsersEnabled, enabled)
		}
		// The summary must not contradict itself: the split has to add up.
		if objects.UsersEnabled+objects.UsersDisabled != objects.Users {
			t.Errorf("%s: %d enabled + %d disabled != %d total — the summary contradicts itself",
				provider, objects.UsersEnabled, objects.UsersDisabled, objects.Users)
		}
	}
}

// TestDisabledAccountsAreMarkedNotDropped covers the arbitration: findings on
// disabled accounts stay visible and keep their severity, but say so.
func TestDisabledAccountsAreMarkedNotDropped(t *testing.T) {
	// PASSWORD_NOT_REQUIRED on DC01: 23 accounts, all 23 disabled.
	allDisabled := Finding{
		Type: "PASSWORD_NOT_REQUIRED", Severity: SeverityCritical, Category: "accounts", Count: 2,
		AffectedEntities: []AffectedEntity{
			{Type: "user", SAMAccountName: "ghost1", Enabled: false},
			{Type: "user", SAMAccountName: "ghost2", Enabled: false},
		},
	}
	// UNCONSTRAINED_DELEGATION on DC01: 20 accounts, 18 disabled.
	mixed := Finding{
		Type: "UNCONSTRAINED_DELEGATION", Severity: SeverityCritical, Category: "accounts", Count: 2,
		AffectedEntities: []AffectedEntity{
			{Type: "user", SAMAccountName: "ghost", Enabled: false},
			{Type: "user", SAMAccountName: "live", Enabled: true},
		},
	}
	noneDisabled := Finding{
		Type: "ASREP_ROASTING_RISK", Severity: SeverityCritical, Category: "accounts", Count: 1,
		AffectedEntities: []AffectedEntity{
			{Type: "user", SAMAccountName: "live", Enabled: true},
		},
	}

	result := &AuditResult{
		Findings:   []Finding{allDisabled, mixed, noneDisabled},
		Statistics: &AuditStatistics{UsersScanned: 3, UsersEnabled: 2, UsersDisabled: 1},
	}
	resp := ConvertToTSFormat(result, "ad", "ldaps://dc01", "DC=example,DC=com", true)

	got := map[string]Finding{}
	for _, f := range resp.Audit.Accounts.Dangerous.Findings {
		got[f.Type] = f
	}
	for _, f := range resp.Audit.Accounts.Status.Findings {
		got[f.Type] = f
	}
	for _, f := range resp.Audit.Accounts.Privileged.Findings {
		got[f.Type] = f
	}
	for _, f := range resp.Audit.Accounts.Service.Findings {
		got[f.Type] = f
	}

	// 1. Nothing is dropped, and severity is untouched — a disabled account
	//    with dangerous rights is a live risk the moment it is re-enabled.
	for _, typ := range []string{"PASSWORD_NOT_REQUIRED", "UNCONSTRAINED_DELEGATION", "ASREP_ROASTING_RISK"} {
		f, ok := got[typ]
		if !ok {
			t.Fatalf("%s disappeared from the report", typ)
		}
		if f.Severity != SeverityCritical {
			t.Errorf("%s: severity = %q, want critical (marking must not downgrade)", typ, f.Severity)
		}
		if len(f.AffectedEntities) == 0 {
			t.Errorf("%s: entities were dropped", typ)
		}
	}

	// 2. The all-disabled finding is marked with counts and a note.
	f := got["PASSWORD_NOT_REQUIRED"]
	if f.Details["disabledAccounts"] != 2 || f.Details["affectedAccounts"] != 2 {
		t.Errorf("PASSWORD_NOT_REQUIRED details = %v, want 2 disabled of 2", f.Details)
	}
	if note, _ := f.Details["disabledAccountsNote"].(string); note == "" {
		t.Errorf("PASSWORD_NOT_REQUIRED: expected a note explaining the marking")
	}

	// 3. The mixed finding reports the split, not just a boolean.
	f = got["UNCONSTRAINED_DELEGATION"]
	if f.Details["disabledAccounts"] != 1 || f.Details["affectedAccounts"] != 2 {
		t.Errorf("UNCONSTRAINED_DELEGATION details = %v, want 1 disabled of 2", f.Details)
	}

	// 4. A finding with no disabled account is left completely alone.
	f = got["ASREP_ROASTING_RISK"]
	if _, marked := f.Details["disabledAccounts"]; marked {
		t.Errorf("ASREP_ROASTING_RISK should carry no disabled marking, got %v", f.Details)
	}
}

// TestAnnotateDisabledAccountsIgnoresNonAccounts — ACL entries, GPOs and the
// like have no meaningful enabled state and must not be counted as disabled.
func TestAnnotateDisabledAccountsIgnoresNonAccounts(t *testing.T) {
	f := Finding{
		Type: "ACL_WRITEDACL", Severity: SeverityHigh, Count: 2,
		AffectedEntities: []AffectedEntity{
			{Type: "aclEntry", Right: "WriteDACL"},
			{Type: "ou", DN: "OU=IT,DC=example,DC=com"},
		},
	}
	annotateDisabledAccounts(&f)
	if _, marked := f.Details["disabledAccounts"]; marked {
		t.Errorf("non-account entities must not be marked disabled, got %v", f.Details)
	}
}
