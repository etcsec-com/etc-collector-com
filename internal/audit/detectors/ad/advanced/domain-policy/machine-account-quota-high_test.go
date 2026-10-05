package domainpolicy

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// MACHINE_ACCOUNT_QUOTA_HIGH fires only when ms-DS-MachineAccountQuota is
// strictly greater than the vendor default of 10 - a deliberate increase
// above the out-of-the-box value. Boundaries (10/11) are literal here, not
// the defaultMachineQuota constant, so a drift in that constant's value
// cannot silently pass this test.
func TestMachineAccountQuotaHigh(t *testing.T) {
	tests := []struct {
		name         string
		domainInfo   *types.DomainInfo
		wantCount    int
		wantSeverity types.Severity
	}{
		{
			name:         "nil DomainInfo reports an explicit collection failure, not a silent pass",
			domainInfo:   nil,
			wantCount:    0,
			wantSeverity: types.SeverityHigh,
		},
		{
			name:         "quota at the default boundary (10) does not fire",
			domainInfo:   &types.DomainInfo{MachineAccountQuota: 10},
			wantCount:    0,
			wantSeverity: types.SeverityHigh,
		},
		{
			name:         "quota one above the default boundary (11) fires",
			domainInfo:   &types.DomainInfo{MachineAccountQuota: 11},
			wantCount:    1,
			wantSeverity: types.SeverityHigh,
		},
		{
			name:         "realistic elevated quota (50) fires",
			domainInfo:   &types.DomainInfo{MachineAccountQuota: 50},
			wantCount:    1,
			wantSeverity: types.SeverityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{DomainInfo: tt.domainInfo}
			findings := NewMachineAccountQuotaHighDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding from Detect (Count-based filtering happens in the engine, not here), got %d", len(findings))
			}
			if findings[0].Count != tt.wantCount {
				t.Fatalf("Count = %d, want %d", findings[0].Count, tt.wantCount)
			}
			if findings[0].Severity != tt.wantSeverity {
				t.Fatalf("Severity = %q, want %q", findings[0].Severity, tt.wantSeverity)
			}
		})
	}
}
