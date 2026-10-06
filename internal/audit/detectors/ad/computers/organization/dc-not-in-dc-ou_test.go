package organization

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDCNotInDCOU_RealDCInDCOUIsNotFlagged covers a false positive
// (allume_a_tort=true): the detector read c.DistinguishedName, an "alias
// for DN" field parseComputer never assigns - only DN is populated. On
// real pipeline data DistinguishedName is always "", so isInDCOU was always
// false and every real DC (correctly placed in the Domain Controllers OU)
// was wrongly flagged High.
func TestDCNotInDCOU_RealDCInDCOUIsNotFlagged(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				// Only DN set, matching what parseComputer actually
				// produces - DistinguishedName is deliberately left empty.
				DN:             "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com",
				SAMAccountName: "DC01$",
			},
		},
	}

	findings := NewDCNotInDCOUDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 (real DC correctly placed in the DC OU), got %d", findings[0].Count)
	}
}

// TestDCNotInDCOU_FiresOnRealMisplacedDC guards against over-filtering: a
// DC genuinely outside the Domain Controllers OU must still fire.
func TestDCNotInDCOU_FiresOnRealMisplacedDC(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:             "CN=DC02,OU=Servers,DC=contoso,DC=com",
				SAMAccountName: "DC02$",
			},
		},
	}

	findings := NewDCNotInDCOUDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (DC outside the DC OU), got %d", findings[0].Count)
	}
}
