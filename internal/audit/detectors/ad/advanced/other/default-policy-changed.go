package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Default GPO GUIDs
const (
	defaultDomainPolicyGUID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
	defaultDCPolicyGUID     = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
)

// DefaultPolicyChangedDetector checks for modifications to default domain policies
type DefaultPolicyChangedDetector struct {
	audit.BaseDetector
}

// NewDefaultPolicyChangedDetector creates a new detector
func NewDefaultPolicyChangedDetector() *DefaultPolicyChangedDetector {
	return &DefaultPolicyChangedDetector{
		BaseDetector: audit.NewBaseDetector("DEFAULT_DOMAIN_POLICY_CHANGED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection. A default GPO (Default Domain Policy or
// Default Domain Controllers Policy) modified within the last 7 days is
// flagged, using the AD whenChanged attribute now collected on types.GPO
// (GPO.WhenChanged was declared nowhere and the provider
// never requested whenChanged, so this detector was structurally stuck at
// Count:0).
func (d *DefaultPolicyChangedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	threshold := data.Now.AddDate(0, 0, -7)

	var defaultGPOs []types.GPO

	for _, gpo := range data.GPOs {
		guidUpper := strings.ToUpper(gpo.GUID)
		cnUpper := strings.ToUpper(gpo.CN)

		if guidUpper == strings.ToUpper(defaultDomainPolicyGUID) ||
			guidUpper == strings.ToUpper(defaultDCPolicyGUID) ||
			cnUpper == strings.ToUpper(defaultDomainPolicyGUID) ||
			cnUpper == strings.ToUpper(defaultDCPolicyGUID) {
			if !gpo.WhenChanged.IsZero() && gpo.WhenChanged.After(threshold) {
				defaultGPOs = append(defaultGPOs, gpo)
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Default Domain Policy Modified",
		Description: "The Default Domain Policy or Default Domain Controllers Policy has been recently modified. Changes to these built-in GPOs affect all domain objects and should be carefully reviewed.",
		Count:       len(defaultGPOs),
	}

	if data.IncludeDetails && len(defaultGPOs) > 0 {
		finding.AffectedEntities = helpers.ToAffectedGPOEntities(defaultGPOs)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDefaultPolicyChangedDetector())
}
