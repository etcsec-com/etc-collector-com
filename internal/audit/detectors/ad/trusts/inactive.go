package trusts

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// trustInactiveThresholdDays - the Trust type has no whenChanged/last-used
// field, but pwdLastSet (types.Trust.PasswordLastSet, collected for ANSSI
// R42) is a real, already collected proxy: Windows
// auto-rotates a trust's inter-domain password every 30 days while the
// trust is alive, so a stale pwdLastSet indicates either broken rotation
// or an abandoned trust nobody maintains.
const trustInactiveThresholdDays = 180

// InactiveDetector detects inactive trust relationships
type InactiveDetector struct {
	audit.BaseDetector
}

// NewInactiveDetector creates a new detector
func NewInactiveDetector() *InactiveDetector {
	return &InactiveDetector{
		BaseDetector: audit.NewBaseDetector("TRUST_INACTIVE", audit.CategoryTrusts),
	}
}

// Detect executes the detection
func (d *InactiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string

	for _, t := range data.Trusts {
		// Skip when pwdLastSet was unreadable (LDAP perm denied / not
		// collected) rather than guessing - an unset value is not evidence
		// of inactivity.
		if t.PasswordLastSet.IsZero() {
			continue
		}
		age := data.Now.Sub(t.PasswordLastSet).Hours() / 24
		if age >= trustInactiveThresholdDays {
			affectedNames = append(affectedNames, t.TargetDomain)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Inactive Trust Relationship",
		Description: "Trust relationship's password has not been rotated in over 180 days. May indicate an abandoned or forgotten trust that should be reviewed for necessity.",
		Count:       len(affectedNames),
	}

	if len(affectedNames) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Review necessity of inactive trusts. Remove trusts that are no longer needed to reduce attack surface.",
		}
	}

	if data.IncludeDetails && len(affectedNames) > 0 {
		entities := make([]types.AffectedEntity, len(affectedNames))
		for i, name := range affectedNames {
			entities[i] = types.AffectedEntity{
				Type:        "trust",
				DisplayName: name,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInactiveDetector())
}
