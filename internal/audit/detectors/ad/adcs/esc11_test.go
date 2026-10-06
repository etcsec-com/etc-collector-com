package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestESC11_SeverityIsInformational covers the ecart: IF_ENFORCEENCRYPTICERTREQUEST
// is a per-CA registry flag (Microsoft Learn, Defender for Identity -
// "Enforce encryption for RPC certificate enrollment interface (ESC11)") that
// is on by default and has no LDAP-readable counterpart - Microsoft's own
// assessment for this same flag requires a sensor installed on the AD CS
// server, confirming directory data alone cannot determine its state. Before
// the fix, this detector reported Severity Medium on every domain with any
// certificate template, regardless of the real (on-by-default) flag value -
// a permanent, content-free "vulnerability" claim. It must now read as a
// manual-verification/product signal, not a determined finding.
func TestESC11_SeverityIsInformational(t *testing.T) {
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{
			{DN: "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"},
		},
	}

	findings := NewESC11Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Fatalf("severity = %q, want %q - IF_ENFORCEENCRYPTICERTREQUEST cannot be read via LDAP and is on by default, so this must not claim a determined vulnerability", findings[0].Severity, types.SeverityInfo)
	}
	if findings[0].Count != 1 {
		t.Fatalf("count = %d, want 1 when certificate templates exist", findings[0].Count)
	}
}
