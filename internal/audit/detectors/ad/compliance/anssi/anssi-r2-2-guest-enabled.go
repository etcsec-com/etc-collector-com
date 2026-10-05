package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Sub-recommendation of ANSSI PA-022 (R2.2). These are the fine-grained
// checks behind the main R-codes that auditors PASSI typically drill into
// during qualification audits.
//
// v3.1.21 dedup - ANSSI_R2_1_BUILTIN_ADMIN_NOT_RENAMED removed (same check
// as M12_DEFAULT_ADMIN_NOT_RENAMED). Mapping migrated (M12 now maps to
// both GP-042 M12 and PA-099 R44).

// --- R2.2: Guest account enabled ---

type R22GuestEnabledDetector struct{ audit.BaseDetector }

func NewR22GuestEnabledDetector() *R22GuestEnabledDetector {
	return &R22GuestEnabledDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R2_2_GUEST_ENABLED", audit.CategoryCompliance)}
}
func (d *R22GuestEnabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	for _, u := range data.Users {
		if strings.HasSuffix(u.ObjectSID, "-501") && !u.Disabled {
			count = 1
			break
		}
	}
	return wrapFinding(d, "ANSSI R2.2 - Compte Guest activé",
		"ANSSI R2.2 (sub-reco) requires the built-in Guest account (RID 501) to be permanently disabled.",
		types.SeverityHigh, count, nil)
}

func init() {
	audit.MustRegister(NewR22GuestEnabledDetector())
}
