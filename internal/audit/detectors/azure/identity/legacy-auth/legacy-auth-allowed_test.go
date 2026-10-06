package legacyauth

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// A block policy scoped to a subset of users must NOT extinguish the
// finding: the rest of the tenant is still exposed to legacy auth. The
// detector previously ignored policy.IncludeUsers entirely (unlike its
// sibling LEGACY_AUTH_NO_CA_BLOCK, which already required "All").
func TestLegacyAuthAllowed_ScopedBlockDoesNotSuppressFinding(t *testing.T) {
	d := NewLegacyAuthAllowedDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:          "enabled",
				IncludeUsers:   []string{"6f1a...-finance-group"}, // scoped, not "All"
				ClientAppTypes: []string{"exchangeActiveSync", "other"},
				GrantControls:  []string{"block"},
			},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 1 {
		t.Fatalf("expected 1 (still exposed outside policy scope), got %d", f.Count)
	}
}

// A block policy that targets All users still correctly extinguishes it.
func TestLegacyAuthAllowed_TenantWideBlockSuppressesFinding(t *testing.T) {
	d := NewLegacyAuthAllowedDetector()
	data := &audit.DetectorData{
		AzureConditionalAccessPolicies: []types.ConditionalAccessPolicy{
			{
				State:          "enabled",
				IncludeUsers:   []string{"All"},
				ClientAppTypes: []string{"exchangeActiveSync", "other"},
				GrantControls:  []string{"block"},
			},
		},
	}
	f := d.Detect(context.Background(), data)[0]
	if f.Count != 0 {
		t.Fatalf("expected 0, got %d", f.Count)
	}
}
