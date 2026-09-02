package membership

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PreWindows2000AccessDetector checks for Pre-Windows 2000 Compatible Access membership
type PreWindows2000AccessDetector struct {
	audit.BaseDetector
}

// NewPreWindows2000AccessDetector creates a new detector
func NewPreWindows2000AccessDetector() *PreWindows2000AccessDetector {
	return &PreWindows2000AccessDetector{
		BaseDetector: audit.NewBaseDetector("PRE_WINDOWS_2000_ACCESS", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *PreWindows2000AccessDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Find the "Pre-Windows 2000 Compatible Access" group by CN
	var targetGroup *types.Group
	for i := range data.Groups {
		cn := strings.ToLower(data.Groups[i].CN)
		sam := strings.ToLower(data.Groups[i].SAMAccountName)
		if strings.Contains(cn, "pre-windows 2000 compatible access") ||
			strings.Contains(sam, "pre-windows 2000 compatible access") {
			targetGroup = &data.Groups[i]
			break
		}
	}

	memberCount := 0
	if targetGroup != nil {
		memberCount = len(targetGroup.Members)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Pre-Windows 2000 Compatible Access",
		Description: "Pre-Windows 2000 Compatible Access group has members. Overly permissive read access to AD objects.",
		Count:       memberCount,
	}

	if data.IncludeDetails && targetGroup != nil && memberCount > 0 {
		finding.AffectedEntities = []types.AffectedEntity{
			types.GroupToAffectedEntity(targetGroup),
		}
		finding.Details = map[string]interface{}{
			"members": targetGroup.Members,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPreWindows2000AccessDetector())
}
