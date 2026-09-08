package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// The CIS Microsoft Windows Server Benchmark recommends a 14-character
// minimum password length, not the 12 this detector was hard-coded to. A
// domain set at exactly 12 was therefore reported as compliant even though
// it is under the current recommendation. This test fails against the old
// threshold (12 -> Count=0) and passes once it is raised to 14 (12 -> Count=1).
func TestWeakPasswordPolicy_ThresholdIs14NotStale12(t *testing.T) {
	cases := []struct {
		name      string
		minLength int
		wantCount int
	}{
		{"minLength=12 -> weak under current CIS recommendation", 12, 1},
		{"minLength=13 -> still weak", 13, 1},
		{"minLength=14 -> compliant", 14, 0},
		{"minLength=16 -> compliant", 16, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := &audit.DetectorData{
				DomainInfo: &types.DomainInfo{MinPwdLength: tc.minLength},
			}

			findings := NewWeakPasswordPolicyDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != tc.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, tc.wantCount)
			}
		})
	}
}
