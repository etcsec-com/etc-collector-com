package password

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DictAttackRiskDetector detects accounts showing signs of dictionary attacks
type DictAttackRiskDetector struct {
	audit.BaseDetector
}

// NewDictAttackRiskDetector creates a new detector
func NewDictAttackRiskDetector() *DictAttackRiskDetector {
	return &DictAttackRiskDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_DICT_ATTACK_RISK", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *DictAttackRiskDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Must be enabled
		if u.Disabled {
			continue
		}

		badPwdCount := u.BadPasswordCount

		// Account has been targeted (>3 bad password attempts) or is currently locked
		if badPwdCount > 3 || u.LockedOut {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Dictionary Attack Risk",
		Description: "User accounts showing signs of password guessing attacks (multiple bad password attempts or lockouts). May indicate weak passwords being targeted or ongoing brute-force attacks.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"recommendation": "Review affected accounts for weak passwords. Consider implementing Azure AD Password Protection.",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDictAttackRiskDetector())
}
