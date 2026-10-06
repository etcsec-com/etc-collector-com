package delegation

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestConstrainedDelegation_Fires confirms the detector counts a computer
// carrying a non-empty msDS-AllowedToDelegateTo.
func TestConstrainedDelegation_Fires(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers: []types.Computer{
			{DN: "CN=SVR01,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR01$", AllowedToDelegateTo: []string{"host/target.example.com"}},
		},
	}
	findings := NewConstrainedDelegationDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != "CN=SVR01,OU=Servers,DC=example,DC=com" {
		t.Fatalf("AffectedEntities = %v, want only the delegating computer", f.AffectedEntities)
	}
}

// TestConstrainedDelegation_NoGuardOnEnabled confirms a disabled computer
// carrying msDS-AllowedToDelegateTo still fires: this detector (unlike its
// _ON_DISABLED_ACCOUNT siblings elsewhere in the catalog) has no Enabled
// guard, by design - matches the lab plant t524pos$ (userAccountControl
// 4098, disabled) in docs/security-validation/results/computer-constrained-delegation-v2/VERDICT.md.
func TestConstrainedDelegation_NoGuardOnEnabled(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SVR01,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR01$", Disabled: true, UserAccountControl: 4098, AllowedToDelegateTo: []string{"host/target.example.com"}},
		},
	}
	findings := NewConstrainedDelegationDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 - a disabled computer with a non-empty msDS-AllowedToDelegateTo must still fire, this detector has no Enabled guard", findings[0].Count)
	}
}

// TestConstrainedDelegation_EmptyNotCounted is the literal mutation-kill
// subtest for M1 (dropping the `len(c.AllowedToDelegateTo) > 0` condition so
// every computer counts unconditionally): a computer with a nil
// msDS-AllowedToDelegateTo must never be counted. If M1 is applied, this
// subtest's expected count=0 turns red.
// MUTATION M1 - a restaurer: condition de la ligne 29 de constrained-delegation.go.
func TestConstrainedDelegation_EmptyNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SVR02,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR02$", AllowedToDelegateTo: nil},
		},
	}
	findings := NewConstrainedDelegationDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 - a computer with nil msDS-AllowedToDelegateTo must not be counted (mutation M1 kill)", findings[0].Count)
	}
}

// TestConstrainedDelegation_DisabledWithoutAttributeNotCounted mirrors the
// lab negative witness (t524ok$ in the same VERDICT): disabled state alone,
// without the attribute, must not fire either.
func TestConstrainedDelegation_DisabledWithoutAttributeNotCounted(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SVR03,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR03$", Disabled: true, UserAccountControl: 4098},
		},
	}
	findings := NewConstrainedDelegationDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0", findings[0].Count)
	}
}

// TestConstrainedDelegation_SeverityAndCategory guards the finding's fixed
// fields read independently in Étape 0 of the VERDICT.
func TestConstrainedDelegation_SeverityAndCategory(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SVR01,OU=Servers,DC=example,DC=com", SAMAccountName: "SVR01$", AllowedToDelegateTo: []string{"host/target.example.com"}},
		},
	}
	findings := NewConstrainedDelegationDetector().Detect(context.Background(), data)
	f := findings[0]
	if f.Severity != types.SeverityCritical {
		t.Fatalf("Severity = %q, want %q", f.Severity, types.SeverityCritical)
	}
	if f.Category != string(audit.CategoryComputers) {
		t.Fatalf("Category = %q, want %q", f.Category, audit.CategoryComputers)
	}
	if f.Type != "COMPUTER_CONSTRAINED_DELEGATION" {
		t.Fatalf("Type = %q, want COMPUTER_CONSTRAINED_DELEGATION", f.Type)
	}
}
