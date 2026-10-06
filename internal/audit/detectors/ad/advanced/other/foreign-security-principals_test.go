package other

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// The old description flatly claimed every FSP came "from external
// forests" with "potential for cross-forest privilege escalation" - but
// Windows creates the identical placeholder object for well-known SIDs
// (Everyone, Authenticated Users, ...) referenced in any ACL, which the
// collector cannot tell apart from a real external-forest principal (it
// only exposes a count, no per-object SID). This test fails against the
// old unconditional "external forests" claim and passes once the
// description discloses the well-known-SID caveat instead.
func TestForeignSecurityPrincipals_DoesNotClaimExternalForestUnconditionally(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{ForeignSecurityPrincipalsCount: 5},
	}

	findings := NewForeignSecurityPrincipalsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 5 {
		t.Fatalf("Count = %d, want 5 (count itself is unchanged)", findings[0].Count)
	}
	desc := findings[0].Description
	if !strings.Contains(desc, "well-known") {
		t.Fatalf("description should disclose the well-known-SID noise caveat, got %q", desc)
	}
}
