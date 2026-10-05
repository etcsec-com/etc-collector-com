package cis

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func compliantPasswordPolicy() *types.DomainInfo {
	return &types.DomainInfo{
		MinPwdLength:     14,
		PwdHistoryLength: 24,
		MaxPwdAge:        90,
		MinPwdAge:        1,
		LockoutThreshold: 5,
	}
}

// TestPasswordPolicy_MaxAge90_NotFlagged: the CIS Benchmark
// requires maximum password age <= 365 days (not 0), not <= 60 - 60 belongs
// to the DISA STIG variant of the benchmark. A domain with MaxPwdAge=90 was
// previously (wrongly) flagged under the 60-day threshold.
func TestPasswordPolicy_MaxAge90_NotFlagged(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: compliantPasswordPolicy()}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0 (MaxPwdAge=90 is CIS-compliant, <=365)", findings)
	}
}

// TestPasswordPolicy_MaxAge400_Flagged is the regression check for a
// genuinely too-long max age.
func TestPasswordPolicy_MaxAge400_Flagged(t *testing.T) {
	info := compliantPasswordPolicy()
	info.MaxPwdAge = 400
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (MaxPwdAge=400 > 365)", findings)
	}
}

// TestPasswordPolicy_LockoutThresholdZero_Flagged: CIS 1.2.2
// explicitly excludes 0 ("unacceptable") from the compliant range, but the
// old code exempted LockoutThreshold==0 from the check entirely - a domain
// with account lockout disabled outright was reported as compliant.
func TestPasswordPolicy_LockoutThresholdZero_Flagged(t *testing.T) {
	info := compliantPasswordPolicy()
	info.LockoutThreshold = 0
	data := &audit.DetectorData{DomainInfo: info}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 1 {
		t.Fatalf("got %+v, want Count=1 (LockoutThreshold=0 must be flagged, not exempted)", findings)
	}
}

// TestPasswordPolicy_FullyCompliant_NoFinding is the regression check for a
// properly configured domain.
func TestPasswordPolicy_FullyCompliant_NoFinding(t *testing.T) {
	data := &audit.DetectorData{DomainInfo: compliantPasswordPolicy()}
	findings := NewPasswordPolicyDetector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("got %+v, want Count=0", findings)
	}
}
