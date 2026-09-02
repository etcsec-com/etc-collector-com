package password

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NotRequiredDetector detects accounts that do not require a password
type NotRequiredDetector struct {
	audit.BaseDetector
}

// NewNotRequiredDetector creates a new detector
func NewNotRequiredDetector() *NotRequiredDetector {
	return &NotRequiredDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_NOT_REQUIRED", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *NotRequiredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// PASSWD_NOTREQD flag (UAC 0x20)
	const uacPasswdNotReqd = 0x20

	var affected []types.User

	for _, u := range data.Users {
		// Check UAC flag for PASSWD_NOTREQD
		if (u.UserAccountControl & uacPasswdNotReqd) != 0 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Password Not Required",
		Description: "User accounts that do not require a password (UAC flag 0x20). Attackers can authenticate without credentials.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNotRequiredDetector())
}
