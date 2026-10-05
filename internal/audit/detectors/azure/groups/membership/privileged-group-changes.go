package membership

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrivilegedChangesDetector checks for privileged groups without change monitoring
type PrivilegedChangesDetector struct {
	audit.BaseDetector
}

// NewPrivilegedChangesDetector creates a new detector
func NewPrivilegedChangesDetector() *PrivilegedChangesDetector {
	return &PrivilegedChangesDetector{
		BaseDetector: audit.NewBaseDetector("AZ_GROUP_PRIVILEGED_CHANGES", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *PrivilegedChangesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	count := 0
	hasPrivilegedGroups := false

	// Check if any privileged groups exist. AdminCount is the AD-side signal
	// (never set by the Azure provider); AzureIsAssignableToRole is the Graph
	// equivalent for Entra role-assignable groups, already collected via the
	// group $select (see internal/providers/azure/client.go).
	for _, group := range data.Groups {
		if group.AdminCount || (group.AzureIsAssignableToRole != nil && *group.AzureIsAssignableToRole) {
			hasPrivilegedGroups = true
			break
		}
	}

	// Informational/advisory: privileged group membership changes should be monitored
	if hasPrivilegedGroups {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Privileged Groups Without Change Monitoring",
		Description: "Privileged group membership changes should be monitored and alerted.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrivilegedChangesDetector())
}
