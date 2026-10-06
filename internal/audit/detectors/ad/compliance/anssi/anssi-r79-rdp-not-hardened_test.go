package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// --- R79 relabeling + no-data false positive ---

// TestR79RDPHardened_NoDataAtAll_NoFalsePositive: with no
// GPOPolicies at all (SMB/SYSVOL not collected), both the highEnc and rpcEnc
// signals default to false, and the detector used to report a guaranteed
// "not hardened" finding indistinguishable from a real violation. Absence of
// evidence must not be reported as a violation (same principle as the R4/R13
// no-data fix in r4-logging.go).
func TestR79RDPHardened_NoDataAtAll_NoFalsePositive(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: nil}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when no GPO data was collected at all, got %+v", findings)
	}
}

// TestR79RDPHardened_WeakSettingsPresent_StillFlagged is the regression
// check: when GPO data IS present and genuinely doesn't set the required
// encryption, the finding must still fire.
func TestR79RDPHardened_WeakSettingsPresent_StillFlagged(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count == 0 {
		t.Fatalf("expected a flagged finding, got %+v", findings)
	}
}

// TestR79RDPHardened_DoesNotClaimANSSIR79: this detector checks
// server-side RDP encryption (MinEncryptionLevel/fEncryptRPCTraffic), but
// ANSSI R79 (p.104-105) is about hardening the RDP CLIENT (graphics
// acceleration, clipboard/smart-card redirection) - an entirely different,
// uncollected set of settings. The finding must not attribute this check to
// R79.
func TestR79RDPHardened_DoesNotClaimANSSIR79(t *testing.T) {
	data := &audit.DetectorData{GPOPolicies: map[string]*audit.GPOPolicy{
		"{gpo}": {RegistrySettings: &audit.RegistrySettings{}},
	}}
	d := NewR79RDPHardenedDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	title := findings[0].Title
	if strings.Contains(title, "R79") {
		t.Errorf("title still attributes this check to ANSSI R79: %q", title)
	}
	if !strings.Contains(findings[0].Description, "NOT a measurement of ANSSI R79") {
		t.Errorf("description should explicitly disclaim R79 attribution, got %q", findings[0].Description)
	}
}
