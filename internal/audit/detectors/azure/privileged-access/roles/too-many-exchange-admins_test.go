package roles

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestTooManyExchangeAdmins(t *testing.T) {
	detector := NewTooManyExchangeAdminsDetector()
	roleID := types.AzureRoleExchangeAdmin
	threshold := 3

	t.Run("below_threshold", func(t *testing.T) {
		data := &audit.DetectorData{AzureRoleAssignments: buildAssignments(roleID, threshold)}
		f := detector.Detect(context.Background(), data)[0]
		if f.Count != 0 {
			t.Fatalf("expected 0 at threshold, got %d", f.Count)
		}
	})
	t.Run("above_threshold", func(t *testing.T) {
		data := &audit.DetectorData{AzureRoleAssignments: buildAssignments(roleID, threshold+1)}
		f := detector.Detect(context.Background(), data)[0]
		if f.Count != threshold+1 {
			t.Fatalf("expected %d above threshold, got %d", threshold+1, f.Count)
		}
	})
	t.Run("ignores_other_roles", func(t *testing.T) {
		data := &audit.DetectorData{AzureRoleAssignments: buildAssignments("unrelated-role", 10)}
		f := detector.Detect(context.Background(), data)[0]
		if f.Count != 0 {
			t.Fatalf("expected 0 for unrelated role, got %d", f.Count)
		}
	})
}
