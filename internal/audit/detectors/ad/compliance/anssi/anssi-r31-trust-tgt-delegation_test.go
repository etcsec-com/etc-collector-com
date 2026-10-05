package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR31TGTDelegation_CitesR26AndFlagsIncomingOnly: the real
// R31 in PA-099 is about SYSVOL script secrets, unrelated; the actual
// "forbid Kerberos delegation across a trust" rule is R26 (p.43), scoped to
// INCOMING trusts specifically - not "any forest trust" regardless of
// direction, which is what the old implementation checked. This test would
// have FAILED against the old implementation (an outbound-only forest trust
// was flagged) and passes now that only incoming trusts are considered, and
// the citation/description no longer claims the unverifiable bit names.
func TestR31TGTDelegation_CitesR26AndFlagsIncomingOnly(t *testing.T) {
	data := &audit.DetectorData{
		Trusts: []types.Trust{
			{TrustType: "Forest", TrustDirection: "Outbound", SelectiveAuth: false},
		},
	}
	findings := NewR31TrustTGTDelegationDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected an outbound-only forest trust to be out of R26's incoming-only scope, got %+v", findings)
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "R31") || strings.Contains(desc, "R31 ") {
		t.Errorf("finding must not cite ANSSI R31 (real R31 is unrelated SYSVOL script secrets), got title=%q", title)
	}
	if strings.Contains(desc, "0x200") || strings.Contains(desc, "0x800") || strings.Contains(desc, "AUTH_TARGET_VALIDATION") {
		t.Errorf("description must not cite bit values/attribute names absent from PA-099, got desc=%q", desc)
	}
}
