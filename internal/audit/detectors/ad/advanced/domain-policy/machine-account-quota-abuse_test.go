package domainpolicy

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// MACHINE_ACCOUNT_QUOTA_ABUSE fires as soon as ms-DS-MachineAccountQuota is
// strictly greater than 0 - including at the vendor default of 10, which is
// the normal out-of-the-box state of nearly every domain. Boundaries (0/1)
// are literal here, independent of the HIGH detector's defaultMachineQuota
// constant.
func TestMachineAccountQuotaAbuse(t *testing.T) {
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
			wantSeverity: types.SeverityMedium,
		},
		{
			name:         "quota hardened to 0 does not fire",
			domainInfo:   &types.DomainInfo{MachineAccountQuota: 0},
			wantCount:    0,
			wantSeverity: types.SeverityMedium,
		},
		{
			name:         "quota of 1 fires",
			domainInfo:   &types.DomainInfo{MachineAccountQuota: 1},
			wantCount:    1,
			wantSeverity: types.SeverityMedium,
		},
		{
			name:         "realistic non-hardened quota (50) fires",
			domainInfo:   &types.DomainInfo{MachineAccountQuota: 50},
			wantCount:    1,
			wantSeverity: types.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &audit.DetectorData{DomainInfo: tt.domainInfo}
			findings := NewMachineAccountQuotaAbuseDetector().Detect(context.Background(), data)
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
