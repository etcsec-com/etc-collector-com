package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func strPtr(s string) *string { return &s }

func TestPublicMembership_NoGroups(t *testing.T) {
	d := NewPublicMembershipDetector()
	data := &audit.DetectorData{}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 on empty tenant, got %d", f.Count)
	}
}

func TestPublicMembership_AllPrivate(t *testing.T) {
	d := NewPublicMembershipDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DisplayName: "Finance", AzureVisibility: strPtr("Private")},
			{DisplayName: "HR", AzureVisibility: strPtr("HiddenMembership")},
			{DisplayName: "Legacy", AzureVisibility: nil},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0 when no group is Public, got %d", f.Count)
	}
}

func TestPublicMembership_PublicGroupDetected(t *testing.T) {
	d := NewPublicMembershipDetector()
	data := &audit.DetectorData{
		Groups: []types.Group{
			{DisplayName: "Private Team", AzureVisibility: strPtr("Private")},
			{DisplayName: "Open Club", AzureVisibility: strPtr("Public")},
			{DisplayName: "open-lowercase", AzureVisibility: strPtr("public")},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 2 {
		t.Fatalf("expected 2 public groups, got %d", f.Count)
	}
	if f.Severity != types.SeverityMedium {
		t.Fatalf("expected medium, got %s", f.Severity)
	}
}
