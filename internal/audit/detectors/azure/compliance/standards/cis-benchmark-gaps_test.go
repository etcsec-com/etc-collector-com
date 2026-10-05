package standards

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AZ_CIS_BENCHMARK_GAPS - when GetConditionalAccessPolicies fails
// (403/timeout), data.AzureConditionalAccessPolicies stays nil. Before the
// fix, checks 2-4 read that nil slice exactly like "zero CA policies exist"
// and counted 3 false gaps on top of whatever check 1 found. Pin Security
// Defaults as enabled (no gap from check 1) so only the CA-policy-dependent
// checks are under test.
func TestCISBenchmarkGaps_SkipsCAChecksOnCollectionFailure(t *testing.T) {
	d := NewCISBenchmarkGapsDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			SecurityDefaults: &types.TenantSecurityDefaults{IsEnabled: true},
		},
		AzureConditionalAccessPolicies: nil,
		Warnings: []types.Warning{
			{Code: "AZURE_CONDITIONAL_ACCESS_POLICIES_FAILED", Message: "403 Forbidden"},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("collection failure must not be counted as 3 CIS gaps, got Count=%d", findings[0].Count)
	}
}

// Same nil/empty AzureConditionalAccessPolicies, but no collection-failure
// warning this time: the tenant genuinely has zero CA policies. The 3 CA
// checks must still fire - the fix must not silence real gaps.
func TestCISBenchmarkGaps_StillFiresOnGenuinelyEmptyPolicies(t *testing.T) {
	d := NewCISBenchmarkGapsDetector()
	data := &audit.DetectorData{
		AzureTenantConfig: &types.AzureTenantConfig{
			SecurityDefaults: &types.TenantSecurityDefaults{IsEnabled: true},
		},
		AzureConditionalAccessPolicies: nil, // collected fine, tenant just has none
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 3 {
		t.Fatalf("expected 3 gaps (no MFA policy, no legacy-auth block, no risk policy), got Count=%d", findings[0].Count)
	}
}
