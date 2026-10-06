package audit

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestBuildAuthMethodsDetail_AllNilReturnsNil(t *testing.T) {
	if got := BuildAuthMethodsDetail(nil, nil, nil); got != nil {
		t.Errorf("all-nil input must return nil to keep JSON output clean, got %#v", got)
	}
}

func TestBuildAuthMethodsDetail_PolicyOnly(t *testing.T) {
	pol := &types.AuthMethodsPolicy{RegistrationEnforcement: true}
	got := BuildAuthMethodsDetail(pol, nil, nil)
	if got == nil || got.Policy == nil || !got.Policy.RegistrationEnforcement {
		t.Fatalf("policy-only mismatch: %#v", got)
	}
	if got.StrengthPolicies != nil || got.UserRegistrationStats != nil {
		t.Errorf("strength/userReg should remain nil, got %#v / %#v", got.StrengthPolicies, got.UserRegistrationStats)
	}
}

func TestSummarizeStrengths_BuiltInVsCustom(t *testing.T) {
	in := []types.AuthStrengthPolicy{
		{ID: "1", PolicyType: "builtIn", DisplayName: "Phishing-resistant MFA"},
		{ID: "2", PolicyType: "builtIn", DisplayName: "Passwordless MFA"},
		{ID: "3", PolicyType: "custom", DisplayName: "Admins-only FIDO2"},
		{ID: "4", PolicyType: "", DisplayName: "Unknown bucket → custom"}, // safety: anything not "builtIn" → custom
	}
	got := summarizeStrengths(in)
	if got.Total != 4 {
		t.Errorf("Total = %d, want 4", got.Total)
	}
	if len(got.BuiltIn) != 2 {
		t.Errorf("BuiltIn len = %d, want 2", len(got.BuiltIn))
	}
	if len(got.Custom) != 2 {
		t.Errorf("Custom len = %d, want 2", len(got.Custom))
	}
}

func TestAggregateUserRegistrations_FullCounters(t *testing.T) {
	users := []types.UserRegistrationDetail{
		{
			UserPrincipalName: "alice@x", IsAdmin: true,
			IsMFACapable: true, IsMFARegistered: true, IsPasswordlessCapable: true,
			MethodsRegistered: []string{"fido2", "microsoftAuthenticatorPush"},
		},
		{
			UserPrincipalName: "bob@x", IsAdmin: false,
			IsMFACapable: true, IsMFARegistered: true,
			MethodsRegistered: []string{"mobilePhone"},
		},
		{
			UserPrincipalName: "carol@x", IsAdmin: true,
			IsMFACapable: true, IsMFARegistered: false,
			MethodsRegistered: []string{"microsoftAuthenticatorPush"},
		},
		{
			UserPrincipalName: "dave@x", IsAdmin: false,
			IsMFACapable: false,
		},
	}
	got := aggregateUserRegistrations(users)

	if got.Total != 4 {
		t.Errorf("Total = %d, want 4", got.Total)
	}
	if got.MFACapable != 3 {
		t.Errorf("MFACapable = %d, want 3", got.MFACapable)
	}
	if got.MFARegistered != 2 {
		t.Errorf("MFARegistered = %d, want 2 (alice, bob)", got.MFARegistered)
	}
	if got.PasswordlessCapable != 1 {
		t.Errorf("PasswordlessCapable = %d, want 1 (alice)", got.PasswordlessCapable)
	}
	if got.FIDO2Registered != 1 {
		t.Errorf("FIDO2Registered = %d, want 1 (alice)", got.FIDO2Registered)
	}
	if got.ByMethod["fido2"] != 1 || got.ByMethod["microsoftAuthenticatorPush"] != 2 || got.ByMethod["mobilePhone"] != 1 {
		t.Errorf("ByMethod mismatch: %v", got.ByMethod)
	}
	// AdminUsers sub-stat: alice + carol
	if got.AdminUsers.Total != 2 {
		t.Errorf("AdminUsers.Total = %d, want 2 (alice + carol)", got.AdminUsers.Total)
	}
	if got.AdminUsers.MFACapable != 2 {
		t.Errorf("AdminUsers.MFACapable = %d, want 2", got.AdminUsers.MFACapable)
	}
	if got.AdminUsers.MFARegistered != 1 {
		t.Errorf("AdminUsers.MFARegistered = %d, want 1 (alice only)", got.AdminUsers.MFARegistered)
	}
	if got.AdminUsers.FIDO2Registered != 1 {
		t.Errorf("AdminUsers.FIDO2Registered = %d, want 1 (alice only)", got.AdminUsers.FIDO2Registered)
	}
}

func TestAggregateUserRegistrations_EmptyInput(t *testing.T) {
	got := aggregateUserRegistrations(nil)
	if got == nil || got.Total != 0 || got.MFACapable != 0 {
		t.Errorf("nil input should produce zero-valued stats, got %#v", got)
	}
	// Maps must be initialised so JSON renders {} not null.
	if got.ByMethod == nil {
		t.Errorf("ByMethod must be non-nil for stable JSON shape")
	}
}

func TestBuildAuthMethodsDetail_FullPayload(t *testing.T) {
	got := BuildAuthMethodsDetail(
		&types.AuthMethodsPolicy{},
		[]types.AuthStrengthPolicy{{ID: "1", PolicyType: "builtIn"}},
		[]types.UserRegistrationDetail{{IsMFACapable: true}},
	)
	if got == nil || got.Policy == nil || got.StrengthPolicies == nil || got.UserRegistrationStats == nil {
		t.Fatalf("full payload mismatch: %#v", got)
	}
	if got.UserRegistrationStats.MFACapable != 1 {
		t.Errorf("MFACapable propagation failed: %d", got.UserRegistrationStats.MFACapable)
	}
	if len(got.StrengthPolicies.BuiltIn) != 1 {
		t.Errorf("BuiltIn propagation failed: %d", len(got.StrengthPolicies.BuiltIn))
	}
}
