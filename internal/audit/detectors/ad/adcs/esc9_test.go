package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC9 is defined by the CT_FLAG_NO_SECURITY_EXTENSION bit of
// msPKI-Enrollment-Flag, not by the template schema version. These cases pin
// that predicate: a schema-2 template that sets the flag must fire, and a
// schema-1 template that does not set the flag must stay silent.
func esc9Count(t *testing.T, tmpl types.CertTemplate) int {
	t.Helper()
	data := &audit.DetectorData{CertTemplates: []types.CertTemplate{tmpl}}
	findings := NewESC9Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0].Count
}

func TestESC9_FiresOnNoSecurityExtensionFlag(t *testing.T) {
	// Schema version 2 (modern) but the flag is set and the template can
	// authenticate: this is the real ESC9 condition and must fire.
	got := esc9Count(t, types.CertTemplate{
		Name:             "ModernButFlagged",
		SchemaVersion:    2,
		EnrollmentFlag:   CTFlagNoSecurityExtension,
		ExtendedKeyUsage: []string{EKUClientAuth},
	})
	if got != 1 {
		t.Fatalf("schema-2 template with CT_FLAG_NO_SECURITY_EXTENSION and auth EKU: want count 1, got %d", got)
	}
}

func TestESC9_SilentOnOldSchemaWithoutFlag(t *testing.T) {
	// Schema version 1 with an auth EKU but WITHOUT the flag: the old
	// schema-version predicate flagged this as a false positive; the correct
	// predicate must stay silent.
	got := esc9Count(t, types.CertTemplate{
		Name:             "LegacyNoFlag",
		SchemaVersion:    1,
		EnrollmentFlag:   0,
		ExtendedKeyUsage: []string{EKUClientAuth},
	})
	if got != 0 {
		t.Fatalf("schema-1 template without the flag must not fire: want count 0, got %d", got)
	}
}

func TestESC9_SilentWhenFlaggedButNoAuthEKU(t *testing.T) {
	// Flag set but no authentication EKU: not exploitable, must stay silent.
	got := esc9Count(t, types.CertTemplate{
		Name:             "FlaggedNoAuth",
		SchemaVersion:    2,
		EnrollmentFlag:   CTFlagNoSecurityExtension,
		ExtendedKeyUsage: []string{"1.3.6.1.5.5.7.3.4"}, // Secure Email only
	})
	if got != 0 {
		t.Fatalf("flagged template without auth EKU must not fire: want count 0, got %d", got)
	}
}
