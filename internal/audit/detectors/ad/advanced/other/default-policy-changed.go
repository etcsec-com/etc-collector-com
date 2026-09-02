package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
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

// Detect executes the detection
// NOTE: This detector currently returns Count=0 because the GPO struct does not include
// a WhenChanged field. To fully implement this detector, add WhenChanged to types.GPO
// and then compare against a threshold (e.g., 7 days) to detect recent modifications.
func (d *DefaultPolicyChangedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var defaultGPOs []types.GPO

	for _, gpo := range data.GPOs {
		guidUpper := strings.ToUpper(gpo.GUID)
		cnUpper := strings.ToUpper(gpo.CN)

		if guidUpper == strings.ToUpper(defaultDomainPolicyGUID) ||
			guidUpper == strings.ToUpper(defaultDCPolicyGUID) ||
			cnUpper == strings.ToUpper(defaultDomainPolicyGUID) ||
			cnUpper == strings.ToUpper(defaultDCPolicyGUID) {
			defaultGPOs = append(defaultGPOs, gpo)
		}
	}

	// TODO: When WhenChanged is added to types.GPO, filter defaultGPOs to only those
	// modified within the last 7 days. For now, we cannot determine modification time,
	// so we return Count=0 to avoid false positives.
	_ = defaultGPOs

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Default Domain Policy Modified",
		Description: "The Default Domain Policy or Default Domain Controllers Policy has been recently modified. Changes to these built-in GPOs affect all domain objects and should be carefully reviewed.",
		Count:       0,
		Details: map[string]interface{}{
			"note": "This detector requires WhenChanged on GPO objects to determine recent modifications. Currently returns no findings.",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDefaultPolicyChangedDetector())
}
