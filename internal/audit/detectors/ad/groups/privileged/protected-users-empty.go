package privileged

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ProtectedUsersEmptyDetector checks for empty Protected Users group
type ProtectedUsersEmptyDetector struct {
	audit.BaseDetector
}

// NewProtectedUsersEmptyDetector creates a new detector
func NewProtectedUsersEmptyDetector() *ProtectedUsersEmptyDetector {
	return &ProtectedUsersEmptyDetector{
		BaseDetector: audit.NewBaseDetector("GROUP_PROTECTED_USERS_EMPTY", audit.CategoryGroups),
	}
}

// Detect executes the detection
func (d *ProtectedUsersEmptyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var protectedUsersGroup *types.Group

	for i := range data.Groups {
		name := data.Groups[i].SAMAccountName
		if name == "" {
			name = data.Groups[i].CN
		}
		if strings.EqualFold(name, "protected users") {
			protectedUsersGroup = &data.Groups[i]
			break
		}
	}

	isEmpty := protectedUsersGroup == nil || len(protectedUsersGroup.Member) == 0

	memberCount := 0
	if protectedUsersGroup != nil {
		memberCount = len(protectedUsersGroup.Member)
	}

	count := 0
	if isEmpty {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Protected Users Group Empty",
		Description: "The Protected Users group has no members. Privileged accounts should be added to this group for enhanced security (NTLM disabled, Kerberos delegation blocked, credential caching prevented).",
		Count:       count,
		Details: map[string]interface{}{
			"memberCount":    memberCount,
			"recommendation": "Add Domain Admins, Enterprise Admins, and other privileged accounts to Protected Users group.",
			"benefits": []string{
				"NTLM authentication disabled",
				"Kerberos delegation blocked",
				"Credential caching prevented",
				"DES/RC4 encryption disabled",
			},
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewProtectedUsersEmptyDetector())
}
