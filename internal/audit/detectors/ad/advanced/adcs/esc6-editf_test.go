package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestESC6Editf_SeverityIsInformational covers the ecart:
// EDITF_ATTRIBUTESUBJECTALTNAME2 is a CA-local registry policy-module flag
// with no LDAP-readable counterpart (Microsoft Learn, Defender for Identity -
// "Edit vulnerable Certificate Authority setting (ESC6)", which itself notes
// its assessment "is available only to customers who installed a sensor on
// an AD CS server" - i.e. even Microsoft's own tooling needs local CA access,
// not just directory data, to read it). Before the fix, this detector
// reported Severity High on every domain with any certificate template,
// regardless of whether the flag was ever set - a permanent, content-free
// "vulnerability" claim; details.note was the only place admitting the
// registry still had to be checked manually. It must now read as a manual-
// verification/product signal, not a determined finding.
func TestESC6Editf_SeverityIsInformational(t *testing.T) {
	data := &audit.DetectorData{
		CertTemplates: []types.CertTemplate{
			{DN: "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"},
		},
	}

	findings := NewESC6EditfDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Fatalf("severity = %q, want %q - EDITF_ATTRIBUTESUBJECTALTNAME2 cannot be read via LDAP, so this must not claim a determined vulnerability", findings[0].Severity, types.SeverityInfo)
	}
	if findings[0].Count != 1 {
		t.Fatalf("count = %d, want 1 when certificate templates exist", findings[0].Count)
	}
}
