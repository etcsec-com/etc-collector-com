package domainpolicy

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestWeakKerberosPolicy_ReadsFromGPOPolicies: the
// detector read data.DomainInfo.MaxTicketAge/MaxRenewAge, two fields no
// provider ever assigns (the real write lands on audit.KerberosPolicy via
// SYSVOL GptTmpl.inf parsing, a different struct). isWeak was therefore
// always "0>10 || 0>7" = false, Count=0 forever, regardless of any real
// weak policy deployed via GPO. Sibling detectors
// (KERBEROS_TICKET_LIFETIME_LONG, KERBEROS_RENEWABLE_TICKET_LONG) already
// use the correct path: helpers.GetKerberosPolicy(data.GPOPolicies) with a
// DomainInfo fallback.
func TestWeakKerberosPolicy_ReadsFromGPOPolicies(t *testing.T) {
	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: "DC=example,DC=com"},
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID-1}": {
				GUID:           "{GUID-1}",
				KerberosPolicy: &audit.KerberosPolicy{MaxTicketAge: 20, MaxRenewAge: 7},
			},
		},
	}

	findings := NewWeakKerberosPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("expected Count=1 (MaxTicketAge=20 > 10), got %d", findings[0].Count)
	}
}

// TestWeakKerberosPolicy_CompliantPolicyDoesNotFire is the sanity check: a
// policy within the recommended bounds must not fire, proving the detector
// isn't simply "always on" once it reads real data.
func TestWeakKerberosPolicy_CompliantPolicyDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: "DC=example,DC=com"},
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID-1}": {
				GUID:           "{GUID-1}",
				KerberosPolicy: &audit.KerberosPolicy{MaxTicketAge: 10, MaxRenewAge: 7},
			},
		},
	}

	findings := NewWeakKerberosPolicyDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("expected Count=0 for a compliant policy (10h/7d), got %d", findings[0].Count)
	}
}
