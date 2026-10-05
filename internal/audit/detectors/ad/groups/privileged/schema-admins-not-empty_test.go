package privileged

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestSchemaAdminsNotEmpty_NoFabricatedANSSICitation covers the fact that
// PA-099 v1.0 has no recommendation about Schema/Enterprise Admins
// membership: R17 (p.35) is Tier 0 patch timeliness, R23 (p.40) is about
// permissions applied TO Tier 0 objects, not their own membership. The
// finding text used to claim "ANSSI PA-099 R17", which is false and
// verifiable in thirty seconds by anyone with the PDF. This test fails
// against that old description and passes once the citation is Microsoft's
// own guidance instead.
func TestSchemaAdminsNotEmpty_NoFabricatedANSSICitation(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Schema Admins", Members: []string{"CN=svc-schema,CN=Users,DC=corp,DC=local"}},
		},
		IncludeDetails: true,
	}

	findings := NewSchemaAdminsNotEmptyDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	desc := findings[0].Description

	if strings.Contains(desc, "ANSSI") {
		t.Fatalf("description must not attribute this check to ANSSI PA-099 (no such recommendation exists), got %q", desc)
	}
	if !strings.Contains(desc, "Microsoft") {
		t.Fatalf("description should cite Microsoft's guidance on Schema/Enterprise Admins membership, got %q", desc)
	}
}

func TestSchemaAdminsNotEmpty_CountsBothGroups(t *testing.T) {
	data := &audit.DetectorData{
		Groups: []types.Group{
			{SAMAccountName: "Schema Admins", Members: []string{"u1"}},
			{SAMAccountName: "Enterprise Admins", Members: []string{"u2", "u3"}},
			{SAMAccountName: "Domain Admins", Members: []string{"u4"}},
		},
		IncludeDetails: true,
	}

	findings := NewSchemaAdminsNotEmptyDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 3 {
		t.Fatalf("Count = %d, want 3 (1 Schema Admins + 2 Enterprise Admins, Domain Admins excluded)", findings[0].Count)
	}
}
