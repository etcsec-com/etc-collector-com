package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EphemeralAdminsDetector detects PAM shadow principal configurations
type EphemeralAdminsDetector struct {
	audit.BaseDetector
}

// NewEphemeralAdminsDetector creates a new detector
func NewEphemeralAdminsDetector() *EphemeralAdminsDetector {
	return &EphemeralAdminsDetector{
		BaseDetector: audit.NewBaseDetector("EPHEMERAL_ADMINS_PAM", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *EphemeralAdminsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Best-effort detection: check if any user has a MemberOf DN containing
	// "Shadow Principal" which indicates PAM shadow principal configuration.
	// Shadow principals are typically under CN=Shadow Principal Configuration,
	// CN=Services,CN=Configuration but we detect them via user membership.
	var affected []types.User
	for _, user := range data.Users {
		for _, dn := range user.MemberOf {
			if containsShadowPrincipal(dn) {
				affected = append(affected, user)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Ephemeral Admin Accounts Detected (PAM Shadow Principals)",
		Description: "Shadow principal configuration detected, indicating Privileged Access Management (PAM) is in use with time-bound privileged group memberships. Review to ensure PAM configuration is intentional and properly managed.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

// containsShadowPrincipal checks if a DN references a shadow principal configuration
func containsShadowPrincipal(dn string) bool {
	lower := strings.ToLower(dn)
	return strings.Contains(lower, "shadow principal")
}

func init() {
	audit.MustRegister(NewEphemeralAdminsDetector())
}
