package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestR23LMHash_CitesR72NotR23 verifies that PA-099's real R23 is
// adminSDHolder/ACL hygiene on Tier 0 accounts, unrelated to LM hash. The
// LAN Manager authentication level setting this detector actually reads
// (LmCompatibilityLevel=5) is prescribed by R72 (p.97-98). This test would
// have FAILED against the old title ("ANSSI R23 - Stockage des hashes LM")
// and passes now that the citation matches what's measured.
func TestR23LMHash_CitesR72NotR23(t *testing.T) {
	d := NewR23LMHashStorageDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "R23") || strings.Contains(desc, "R23 ") {
		t.Errorf("finding must not cite ANSSI R23 (real R23 is unrelated adminSDHolder/ACL hygiene), got title=%q", title)
	}
	if !strings.Contains(title, "R72") && !strings.Contains(desc, "R72") {
		t.Errorf("finding should cite the real source (PA-099 R72), got title=%q desc=%q", title, desc)
	}
}
