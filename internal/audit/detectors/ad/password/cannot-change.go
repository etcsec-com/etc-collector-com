package password

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CannotChangeDetector detects accounts forbidden from changing their password
type CannotChangeDetector struct {
	audit.BaseDetector
}

// NewCannotChangeDetector creates a new detector
func NewCannotChangeDetector() *CannotChangeDetector {
	return &CannotChangeDetector{
		BaseDetector: audit.NewBaseDetector("USER_CANNOT_CHANGE_PASSWORD", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *CannotChangeDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// PASSWD_CANT_CHANGE flag (UAC 0x40)
	const uacPasswdCantChange = 0x40

	var affected []types.User

	for _, u := range data.Users {
		// Check UAC flag for PASSWD_CANT_CHANGE
		if (u.UserAccountControl & uacPasswdCantChange) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "User Cannot Change Password",
		Description: "User accounts forbidden from changing their own password (UAC flag 0x40). Prevents password rotation.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCannotChangeDetector())
}
