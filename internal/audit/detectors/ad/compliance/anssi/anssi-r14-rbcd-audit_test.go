package anssi

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestR14RBCDAudit_ScopedToDomainControllers: ANSSI PA-099 R65
// (p.90-91) flags RBCD specifically when its target is a Tier 0 resource.
// The previous implementation counted RBCD on ANY computer, including
// ordinary Tier 2 member servers where RBCD is a normal, sanctioned
// delegation pattern (e.g. an app server delegating to a print spooler) -
// wildly over-broad relative to what R65 actually prohibits. This test
// would have FAILED against the old implementation (both computers counted)
// and passes now that only RBCD on a domain controller is flagged.
func TestR14RBCDAudit_ScopedToDomainControllers(t *testing.T) {
	dc := types.Computer{DN: "CN=DC01,OU=Domain Controllers,DC=lab,DC=local", SAMAccountName: "DC01$", AllowedToActOnBehalfOfOtherIdentity: []byte{0x01}}
	memberServer := types.Computer{DN: "CN=APP01,OU=Servers,DC=lab,DC=local", SAMAccountName: "APP01$", AllowedToActOnBehalfOfOtherIdentity: []byte{0x01}}
	data := &audit.DetectorData{
		IncludeDetails:    true,
		DomainControllers: []types.Computer{dc},
		Computers:         []types.Computer{dc, memberServer},
	}
	findings := NewR14RBCDAuditDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected only the domain controller's RBCD to be flagged, got %+v", findings)
	}
	if len(findings[0].AffectedEntities) != 1 || findings[0].AffectedEntities[0].DN != dc.DN {
		t.Fatalf("expected the flagged entity to be the DC, got %+v", findings[0].AffectedEntities)
	}
}
