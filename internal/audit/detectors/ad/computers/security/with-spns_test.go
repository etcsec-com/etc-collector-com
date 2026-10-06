package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Kerberoasting a computer account is not practically viable
// (auto-rotated, high-entropy machine password); the prior High severity
// "enables Kerberoasting" claim was noise on nearly every computer with an
// SPN in production.
func TestWithSPNs_NotClaimedAsHighSeverityKerberoasting(t *testing.T) {
	c := types.Computer{DN: "CN=SRV01,DC=example,DC=com", ServicePrincipalNames: []string{"HOST/srv01.example.com"}}
	data := &audit.DetectorData{Computers: []types.Computer{c}}

	findings := NewWithSPNsDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1 (inventory logic unchanged)", f.Count)
	}
	if f.Severity == types.SeverityHigh {
		t.Fatalf("Severity = %q, want downgraded from High: Kerberoasting a computer account is not practically viable", f.Severity)
	}
}
