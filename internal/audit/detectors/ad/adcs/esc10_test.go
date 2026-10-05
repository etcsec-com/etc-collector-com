package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestESC10_SeverityIsInformational covers the ecart: StrongCertificateBinding
// Enforcement is a per-DC registry value (Microsoft Support KB5014754,
// "Certificate-based authentication changes on Windows domain controllers")
// with no LDAP-readable counterpart, so this collector can never observe its
// actual state. Before the fix, this detector reported Severity High on
// every domain regardless of the real enforcement mode - a permanent,
// content-free "vulnerability" claim. It must now read as a manual-
// verification/product signal, matching the SeverityInfo convention this
// codebase uses elsewhere for non-vulnerability reminders (e.g.
// INFO_DOMAIN_CONTROLLER), not a determined High-severity finding.
func TestESC10_SeverityIsInformational(t *testing.T) {
	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: "DC=example,DC=com", DomainSID: "S-1-5-21-1-2-3"},
	}

	findings := NewESC10Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Fatalf("severity = %q, want %q - StrongCertificateBindingEnforcement cannot be read via LDAP, so this must not claim a determined vulnerability", findings[0].Severity, types.SeverityInfo)
	}
	if findings[0].Count != 1 {
		t.Fatalf("count = %d, want 1 when domain info is present", findings[0].Count)
	}
}
