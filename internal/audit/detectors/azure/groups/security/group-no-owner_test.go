package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AZ_GROUP_NO_OWNER used to hard-code count=1 on every run, regardless of
// tenant data. It was retired rather than left fabricating a count, and is
// reinstated here reading the real AzureOwners/AzureOwnersProbed fields the
// provider now populates via GET /groups/{id}/owners.

// Decisive test: a tenant where every probed group has an owner must
// produce NO finding (Count 0) - proof the detector is no longer a
// constant.
func TestGroupNoOwner_SilentWhenAllProbedGroupsHaveOwner(t *testing.T) {
	d := NewNoOwnerDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "G1", AzureOwnersProbed: true, AzureOwners: []string{"alice@corp.com"}},
			{SAMAccountName: "G2", AzureOwnersProbed: true, AzureOwners: []string{"bob@corp.com", "carol@corp.com"}},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding struct, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count 0 when every probed group has an owner, got %d", findings[0].Count)
	}
}

func TestGroupNoOwner_CountsAndNamesGroupsWithoutOwner(t *testing.T) {
	d := NewNoOwnerDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "G-NoOwner1", AzureOwnersProbed: true, AzureOwners: nil},
			{SAMAccountName: "G-NoOwner2", AzureOwnersProbed: true, AzureOwners: []string{}},
			{SAMAccountName: "G-HasOwner", AzureOwnersProbed: true, AzureOwners: []string{"alice@corp.com"}},
		},
		IncludeDetails: true,
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 2 {
		t.Fatalf("expected Count 2 (the two probed, owner-less groups), got %+v", findings)
	}
	if len(findings[0].AffectedEntities) != 2 {
		t.Fatalf("expected 2 named affected entities, got %d", len(findings[0].AffectedEntities))
	}
}

// A group with AzureOwnersProbed==false must never be counted, no matter
// what AzureOwners holds - Probed=false means the question was never put to
// Graph.
func TestGroupNoOwner_UnprobedGroupNeverCounted(t *testing.T) {
	d := NewNoOwnerDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "G-Unprobed", AzureOwnersProbed: false, AzureOwners: nil},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 for an unprobed group regardless of its AzureOwners, got %+v", findings)
	}
}

// On-prem-synced groups structurally have no Entra owner (governance lives
// in the source AD) and must be excluded, or the fix recreates the mass
// false positive the original detector was retired for.
func TestGroupNoOwner_ExcludesOnPremisesSyncedGroups(t *testing.T) {
	d := NewNoOwnerDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "G-Synced", AzureOwnersProbed: true, AzureOwners: nil, AzureOnPremisesSyncEnabled: boolPtr(true)},
			{SAMAccountName: "G-CloudNoOwner", AzureOwnersProbed: true, AzureOwners: nil, AzureOnPremisesSyncEnabled: boolPtr(false)},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected Count 1 (only the cloud-native owner-less group), got %+v", findings)
	}
}

// If owner collection fails entirely (every group left AzureOwnersProbed
// false, e.g. transport failure or budget exhausted), the detector must
// stay silent rather than invent a count - the collector emits its own
// warning (see enrichGroupsWithOwners), the detector itself just sees no
// probed data to work from.
func TestGroupNoOwner_NoFabricatedCountWhenCollectionFailed(t *testing.T) {
	d := NewNoOwnerDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "G1", AzureOwnersProbed: false},
			{SAMAccountName: "G2", AzureOwnersProbed: false},
			{SAMAccountName: "G3", AzureOwnersProbed: false},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected Count 0 when no group was ever probed, got %+v", findings)
	}
}
