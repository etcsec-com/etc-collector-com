package delegation

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Microsoft Defender for Identity explicitly excludes domain
// controllers from its "Unsecure Kerberos delegation" assessment: every DC
// carries unconstrained delegation by design, so flagging it is not a
// finding. The prior version of this detector flagged every DC in every
// domain as Critical.
func TestUnconstrainedDelegation_DomainControllersExcluded(t *testing.T) {
	const domainDN = "DC=example,DC=com"

	dc := types.Computer{
		DN:                   "CN=DC01,OU=Domain Controllers," + domainDN,
		SAMAccountName:       "DC01$",
		TrustedForDelegation: true,
		UserAccountControl:   0x2000, // SERVER_TRUST_ACCOUNT | unconstrained delegation flag would also be set on real DCs
	}
	member := types.Computer{
		DN:                   "CN=APPSRV01,OU=Servers," + domainDN,
		SAMAccountName:       "APPSRV01$",
		TrustedForDelegation: true,
	}

	data := &audit.DetectorData{
		IncludeDetails: true,
		Computers:      []types.Computer{dc, member},
	}

	findings := NewUnconstrainedDelegationDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the member server, not the DC)", f.Count)
	}
	if len(f.AffectedEntities) != 1 || f.AffectedEntities[0].DN != member.DN {
		t.Fatalf("AffectedEntities = %v, want only %q", f.AffectedEntities, member.DN)
	}
}
