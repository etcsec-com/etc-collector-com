package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func stringPtr(s string) *string { return &s }

// AZ_GROUP_OWNER_IS_GUEST used to hard-code count=1 on every run, regardless
// of tenant data. Reinstated here, cross-referencing each group's
// AzureOwners (UPNs, populated by enrichGroupsWithOwners) against the real
// AzureUserType collected on data.Users.

func TestGroupOwnerIsGuest_SilentWhenNoOwnerIsGuest(t *testing.T) {
	d := NewOwnerIsGuestDetector()
	data := &audit.DetectorData{
		Users: []types.User{
			{UserPrincipalName: "alice@corp.com", AzureUserType: stringPtr("Member")},
		},
		Groups: []types.Group{
			{SAMAccountName: "G1", AzureOwnersProbed: true, AzureOwners: []string{"alice@corp.com"}},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 when no resolved owner is a Guest, got %+v", findings)
	}
}

func TestGroupOwnerIsGuest_FlagsGroupWithCrossReferencedGuestOwner(t *testing.T) {
	d := NewOwnerIsGuestDetector()
	data := &audit.DetectorData{
		Users: []types.User{
			{UserPrincipalName: "alice@corp.com", AzureUserType: stringPtr("Member")},
			{UserPrincipalName: "eve_othercorp.com#EXT#@corp.onmicrosoft.com", AzureUserType: stringPtr("Guest")},
		},
		Groups: []types.Group{
			{SAMAccountName: "G-Clean", AzureOwnersProbed: true, AzureOwners: []string{"alice@corp.com"}},
			{SAMAccountName: "G-GuestOwned", AzureOwnersProbed: true, AzureOwners: []string{"alice@corp.com", "eve_othercorp.com#EXT#@corp.onmicrosoft.com"}},
		},
		IncludeDetails: true,
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected Count 1 (only G-GuestOwned), got %+v", findings)
	}
	if len(findings[0].AffectedEntities) != 1 {
		t.Fatalf("expected 1 named affected entity, got %d", len(findings[0].AffectedEntities))
	}
}

// The decisive anti-guessing test: an owner UPN whose domain looks external
// must NOT be flagged unless data.Users actually resolves it as Guest. Here
// it resolves to Member (e.g. a cloud-only account on a custom domain that
// happens to differ from the tenant's primary domain) - a domain-based
// guess would wrongly flag this group.
func TestGroupOwnerIsGuest_DoesNotGuessFromUPNDomain(t *testing.T) {
	d := NewOwnerIsGuestDetector()
	data := &audit.DetectorData{
		Users: []types.User{
			{UserPrincipalName: "bob@partner-looking-domain.com", AzureUserType: stringPtr("Member")},
		},
		Groups: []types.Group{
			{SAMAccountName: "G1", AzureOwnersProbed: true, AzureOwners: []string{"bob@partner-looking-domain.com"}},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0: userType resolved to Member despite an external-looking domain, got %+v", findings)
	}
}

// An owner whose userType cannot be resolved at all (not present in
// data.Users - e.g. a service principal owner) must not be counted either
// way, rather than guessed.
func TestGroupOwnerIsGuest_UnresolvedOwnerNotCounted(t *testing.T) {
	d := NewOwnerIsGuestDetector()
	data := &audit.DetectorData{
		Users: []types.User{},
		Groups: []types.Group{
			{SAMAccountName: "G1", AzureOwnersProbed: true, AzureOwners: []string{"unknown-sp-owner@corp.com"}},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 for an owner with no resolvable userType, got %+v", findings)
	}
}

// A group with AzureOwnersProbed==false must never be counted.
func TestGroupOwnerIsGuest_UnprobedGroupNeverCounted(t *testing.T) {
	d := NewOwnerIsGuestDetector()
	data := &audit.DetectorData{
		Users: []types.User{
			{UserPrincipalName: "eve@corp.com", AzureUserType: stringPtr("Guest")},
		},
		Groups: []types.Group{
			{SAMAccountName: "G-Unprobed", AzureOwnersProbed: false, AzureOwners: []string{"eve@corp.com"}},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 for an unprobed group even if its stale AzureOwners would match a guest, got %+v", findings)
	}
}
