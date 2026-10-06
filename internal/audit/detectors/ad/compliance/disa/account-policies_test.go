package disa

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func compliantAccountPolicy() *types.DomainInfo {
	return &types.DomainInfo{
		MinPwdLength:     14,
		PwdHistoryLength: 24,
		MaxPwdAge:        30,
		LockoutThreshold: 3,
		LockoutDuration:  15,
	}
}

// TestAccountPolicies_LockoutThresholdZero_Flagged: the old
// code exempted LockoutThreshold==0 from the check ("&& != 0"), but the
// Windows Server 2022 STIG (WN22-AC-000020) explicitly excludes 0 from the
// compliant range - an unlimited-attempts lockout policy is the violation,
// not an exemption from it.
func TestAccountPolicies_LockoutThresholdZero_Flagged(t *testing.T) {
	info := compliantAccountPolicy()
	info.LockoutThreshold = 0
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewAccountPoliciesDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (LockoutThreshold=0 must be flagged, not exempted)", findings)
	}
}

// TestAccountPolicies_MaxAgeZero_Flagged is the analogous fix for maximum
// password age: 0 (never expires) must be flagged, matching the WN22-AC-000050
// requirement ("excluding '0'").
func TestAccountPolicies_MaxAgeZero_Flagged(t *testing.T) {
	info := compliantAccountPolicy()
	info.MaxPwdAge = 0
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewAccountPoliciesDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (MaxPwdAge=0/never-expires must be flagged)", findings)
	}
}

// TestAccountPolicies_CitesServerSTIG: the checks used to cite
// V-63419/63423/63429/63433/63437 - the Windows 10 client STIG (two of
// which, V-63433/63437, don't exist in that STIG at all) - while the
// `stig` Details field claimed "Windows Server STIG". This is a domain-wide
// AD account policy, so the citations must reference the actual Windows
// Server STIG.
func TestAccountPolicies_CitesServerSTIG(t *testing.T) {
	info := compliantAccountPolicy()
	info.MinPwdLength = 8 // force a violation to inspect its citation
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewAccountPoliciesDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1", findings)
	}
	if got := findings[0].Details["stig"]; got != "Microsoft Windows Server 2022 STIG (V2R7)" {
		t.Errorf("Details[stig] = %v, want the Windows Server 2022 STIG", got)
	}
	violations, _ := findings[0].Details["violations"].([]string)
	if len(violations) != 1 || violations[0] != "WN22-AC-000070 (V-254291): Minimum password length 8 < 14" {
		t.Errorf("violations = %v, want the WN22-AC-000070/V-254291 citation", violations)
	}
}

// TestAccountPolicies_FullyCompliant_NoFinding is the regression check for a
// properly configured domain.
func TestAccountPolicies_FullyCompliant_NoFinding(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: compliantAccountPolicy()}
	findings := NewAccountPoliciesDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0", findings)
	}
}
