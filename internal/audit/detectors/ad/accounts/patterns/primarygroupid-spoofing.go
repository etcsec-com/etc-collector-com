package patterns

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrimaryGroupIdSpoofingDetector detects primaryGroupID spoofing
type PrimaryGroupIdSpoofingDetector struct {
	audit.BaseDetector
}

// NewPrimaryGroupIdSpoofingDetector creates a new detector
func NewPrimaryGroupIdSpoofingDetector() *PrimaryGroupIdSpoofingDetector {
	return &PrimaryGroupIdSpoofingDetector{
		BaseDetector: audit.NewBaseDetector("PRIMARYGROUPID_SPOOFING", audit.CategoryAccounts),
	}
}

// Detect executes the detection
func (d *PrimaryGroupIdSpoofingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	// Standard primaryGroupID for Domain Users is 513
	const standardPrimaryGroupID = 513

	for _, u := range data.Users {
		if u.PrimaryGroupID != 0 && u.PrimaryGroupID != standardPrimaryGroupID {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "primaryGroupID Spoofing",
		Description: "User accounts with non-standard primaryGroupID. Can be used to hide group membership.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrimaryGroupIdSpoofingDetector())
}
