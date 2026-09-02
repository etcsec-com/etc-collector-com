package policies

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoPolicyAllUsersDetector checks if any CA policy targets all users
type NoPolicyAllUsersDetector struct {
	audit.BaseDetector
}

// NewNoPolicyAllUsersDetector creates a new detector
func NewNoPolicyAllUsersDetector() *NoPolicyAllUsersDetector {
	return &NoPolicyAllUsersDetector{
		BaseDetector: audit.NewBaseDetector("CA_NO_POLICY_ALL_USERS", audit.CategoryConditionalAccess),
	}
}

// Detect executes the detection
func (d *NoPolicyAllUsersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	hasAllUsersPolicy := false

	for _, p := range data.AzureConditionalAccessPolicies {
		if p.State == "enabled" && containsStr(p.IncludeUsers, "All") {
			hasAllUsersPolicy = true
			break
		}
	}

	count := 0
	if !hasAllUsersPolicy {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "No CA Policy Targeting All Users",
		Description: "No enabled Conditional Access policy targets all users. Without comprehensive coverage, users may bypass security controls.",
		Count:       count,
	}

	return []types.Finding{finding}
}

// containsStr checks if a slice contains a string
func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func init() {
	audit.MustRegister(NewNoPolicyAllUsersDetector())
}
