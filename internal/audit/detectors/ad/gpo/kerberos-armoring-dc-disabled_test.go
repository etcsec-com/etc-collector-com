package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestKerberosArmoringDC_RecognizesEnableCbacAndArmor covers a parser bug
// (commit 5be5bea6): the registry.pol parser only recognized
// SupportedEncTypes/SupportedEncryptionTypes under a Kdc-shaped key, a
// combination no real GPO ever writes - the actual value name is
// EnableCbacAndArmor. KerberosArmoringDC was therefore structurally always
// nil and this detector fired Count=1 on every domain, hardened or not.
// This test exercises the detector end-to-end through the real parser to
// pin that a domain with FAST support configured (EnableCbacAndArmor=1
// under the Kdc\Parameters key) is recognized and does not fire.
func TestKerberosArmoringDC_RecognizesEnableCbacAndArmor(t *testing.T) {
	v := 1
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID-1}": {
				GUID: "{GUID-1}",
				RegistrySettings: &audit.RegistrySettings{
					KerberosArmoringDC: &v,
				},
			},
		},
	}

	findings := NewKerberosArmoringDCDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0: FAST support is configured (KerberosArmoringDC=1), must not fire", findings[0].Count)
	}
}

// TestKerberosArmoringDC_UnconfiguredFires pins the positive case: no GPO
// configures the KDC's EnableCbacAndArmor value at all.
func TestKerberosArmoringDC_UnconfiguredFires(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID-1}": {GUID: "{GUID-1}", RegistrySettings: &audit.RegistrySettings{}},
		},
	}

	findings := NewKerberosArmoringDCDetector().Detect(context.Background(), data)
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1: no GPO configures Kerberos armoring on DCs", findings[0].Count)
	}
}
