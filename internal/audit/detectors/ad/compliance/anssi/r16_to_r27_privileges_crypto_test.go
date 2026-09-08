package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestR18GPCO_DoesNotClaimANSSI covers the fact that a full-text audit of
// ANSSI PA-099 found no mention of "Group Policy Creator Owners" anywhere in the
// guide, and the real R18 is about OS security baselines, unrelated. This
// test would have FAILED against the old title/description (claimed
// "ANSSI R18") and passes now that the fabricated attribution is removed.
func TestR18GPCO_DoesNotClaimANSSI(t *testing.T) {
	d := NewR18GPCOMinimalDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "ANSSI") || strings.Contains(desc, "ANSSI R18 ") {
		t.Errorf("finding must not attribute Group Policy Creator Owners hygiene to ANSSI, got title=%q desc=%q", title, desc)
	}
}

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

// TestR27KerberosFAST_CitesR68NotR27 verifies that PA-099's real R27 is
// about regularly running AD control-path analysis tools (BloodHound-class),
// unrelated to Kerberos armoring. The DC+client Kerberos armoring
// requirement this detector actually reads is R68 (p.93-94). This test
// would have FAILED against the old title ("ANSSI R27 - Kerberos FAST
// armoring") and passes now that the citation matches what's measured.
func TestR27KerberosFAST_CitesR68NotR27(t *testing.T) {
	d := NewR27KerberosFASTArmoringDetector()
	findings := d.Detect(context.Background(), &audit.DetectorData{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	title, desc := findings[0].Title, findings[0].Description
	if strings.Contains(title, "R27") || strings.Contains(desc, "R27 ") {
		t.Errorf("finding must not cite ANSSI R27 (real R27 is control-path analysis tooling), got title=%q", title)
	}
	if !strings.Contains(title, "R68") && !strings.Contains(desc, "R68") {
		t.Errorf("finding should cite the real source (PA-099 R68), got title=%q desc=%q", title, desc)
	}
	if strings.Contains(desc, "SupportedEncryptionTypes") {
		t.Errorf("description should no longer claim the wrong DC-side mechanism (SupportedEncryptionTypes), got desc=%q", desc)
	}
}
