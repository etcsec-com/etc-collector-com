package emergency

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestEmergencyCredentialStale_MatchesCurrentMicrosoftGuidance covers the
// source review finding: the previous text ("rotate credentials every 90-180
// days") described password-era practice that Microsoft's current guidance
// (security-emergency-access) has replaced with non-expiring, phishing-
// resistant credentials validated on a 90-day cadence. A description that
// still told operators to "rotate" a passkey/FIDO2 credential would fail
// this; the corrected text does not.
func TestEmergencyCredentialStale_MatchesCurrentMicrosoftGuidance(t *testing.T) {
	d := NewEmergencyCredentialStaleDetector()
	f := d.Detect(context.Background(), &audit.DetectorData{})[0]

	if strings.Contains(f.Description, "90-180 days") {
		t.Fatalf("description still recommends password-era rotation cadence: %q", f.Description)
	}
	if !strings.Contains(f.Description, "90 days") {
		t.Fatalf("description should reference the 90-day validation cadence from Microsoft's current guidance, got %q", f.Description)
	}
	if !strings.Contains(strings.ToLower(f.Description), "phishing-resistant") && !strings.Contains(strings.ToLower(f.Description), "fido2") {
		t.Fatalf("description should reference phishing-resistant/FIDO2 credentials per current guidance, got %q", f.Description)
	}
}
