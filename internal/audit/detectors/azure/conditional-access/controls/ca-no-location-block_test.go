package controls

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CA_NO_LOCATION_BLOCK - before the fix, any enabled policy with a
// locations condition satisfied the check regardless of grant control, even
// if it only required MFA (not blocking) for that location. The title and
// description promise blocking specifically.
func TestNoLocationBlock_MFAOnlyPolicyStillFlagged(t *testing.T) {
	d := NewNoLocationBlockDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:            "enabled",
				IncludeLocations: []string{"untrusted-location-id"},
				GrantControls:    []string{"mfa"}, // requires MFA, does not block
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("a location policy that only requires MFA (doesn't block) must still be flagged as 'no location block', got Count=%d", findings[0].Count)
	}
}

// A genuine location-block policy must silence the check - the fix must not
// produce false positives on the real thing it's looking for.
func TestNoLocationBlock_RealBlockPolicySilencesCheck(t *testing.T) {
	d := NewNoLocationBlockDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:            "enabled",
				IncludeLocations: []string{"untrusted-location-id"},
				GrantControls:    []string{"block"},
			},
		},
	}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("expected exactly 1 finding with Count=0, got %+v", findings)
	}
}
