package anssi

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func compliantPasswordPolicy() *types.DomainInfo {
	return &types.DomainInfo{
		MinPwdLength:     minLengthBenchmark,
		PwdHistoryLength: pwdHistoryBenchmark,
		LockoutThreshold: 5,
		MaxPwdAge:        400, // longer than the old 90-day rule, must not be flagged
	}
}

// The previous implementation explicitly excluded threshold=0 from the
// lockout check (`LockoutThreshold > 5 && LockoutThreshold != 0`), treating
// "no lockout mechanism at all" as compliant. PG-078 R10 requires SOME
// mechanism limiting authentication attempts, so threshold=0 is the worst
// case, not a safe one. This test would have FAILED against the old
// implementation (no finding) and passes against the fix (flagged).
func TestR1PasswordPolicy_NoLockoutThreshold_Flagged(t *testing.T) {
	di := compliantPasswordPolicy()
	di.LockoutThreshold = 0
	data := &audit.DetectorData{DomainInfo: di}
	d := NewR1PasswordPolicyDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected threshold=0 (no lockout mechanism) to be flagged, got %+v", findings)
	}
	violations, _ := findings[0].Details["violations"].([]string)
	found := false
	for _, v := range violations {
		if strings.Contains(v, "No account lockout mechanism") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a violation explaining the missing lockout mechanism, got %v", violations)
	}
}

// PG-078 R24/R25 (p.29-30) recommend NOT imposing a default expiry on
// non-sensitive accounts, and 1-3 years (not <=90 days) when one is imposed
// on privileged accounts. The previous implementation flagged MaxPwdAge>90
// as an "ANSSI R1" violation - contrary to the actual source. This test
// would have FAILED against the old implementation (long max age flagged)
// and passes against the fix (max age is no longer checked here).
func TestR1PasswordPolicy_LongMaxAge_NotFlagged(t *testing.T) {
	di := compliantPasswordPolicy()
	di.MaxPwdAge = 1000 // ~2.7 years, well past the removed 90-day rule
	data := &audit.DetectorData{DomainInfo: di}
	d := NewR1PasswordPolicyDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected max password age to no longer be checked against a fabricated 90-day ANSSI threshold, got %+v", findings)
	}
}

func TestR1PasswordPolicy_WeakLength_Flagged(t *testing.T) {
	di := compliantPasswordPolicy()
	di.MinPwdLength = 8
	data := &audit.DetectorData{DomainInfo: di}
	d := NewR1PasswordPolicyDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("expected weak min length to be flagged, got %+v", findings)
	}
}

func TestR1PasswordPolicy_FullyCompliant_NoFinding(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: compliantPasswordPolicy()}
	d := NewR1PasswordPolicyDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected a fully compliant policy to be clean, got %+v", findings)
	}
}

// PA-099's real R1 (p.28) is "adopter un modèle de gestion des accès à
// privilèges" - unrelated to password-policy thresholds. The finding must
// not claim "ANSSI R1" requires these numbers.
func TestR1PasswordPolicy_DoesNotClaimANSSIR1(t *testing.T) {
	di := compliantPasswordPolicy()
	di.MinPwdLength = 4
	data := &audit.DetectorData{DomainInfo: di}
	d := NewR1PasswordPolicyDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	title := findings[0].Title
	desc := findings[0].Description
	if strings.Contains(title, "ANSSI R1") || strings.Contains(desc, "ANSSI R1 ") || strings.Contains(desc, "ANSSI requires") {
		t.Errorf("finding should not attribute these thresholds to ANSSI R1, got title=%q desc=%q", title, desc)
	}
	if v, ok := findings[0].Details["violations"]; ok {
		if _, hasFramework := findings[0].Details["framework"]; hasFramework {
			t.Errorf("finding Details should no longer hardcode a fabricated ANSSI framework/control attribution, got violations=%v details=%v", v, findings[0].Details)
		}
	}
}
