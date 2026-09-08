package mfa

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDNoFIDO2       = "MFA_NO_FIDO2"
	CategoryNoFIDO2 = audit.CategoryIdentity
)

// NoFIDO2Detector checks if FIDO2 security keys are enabled
type NoFIDO2Detector struct {
	audit.BaseDetector
}

// NewMfaNoFido2Detector creates a new no FIDO2 detector
func NewMfaNoFido2Detector() *NoFIDO2Detector {
	return &NoFIDO2Detector{
		BaseDetector: audit.NewBaseDetector(IDNoFIDO2, CategoryNoFIDO2),
	}
}

// allUsersTargetID is the Microsoft Graph sentinel value used in an
// authenticationMethodTarget's "id" field to mean "every user in the
// tenant" (targetType "group"). Confirmed against Microsoft's own example
// response for GET /policies/authenticationMethodsPolicy (learn.microsoft.
// com/en-us/graph/api/authenticationmethodspolicy-get): includeTargets:
// [{"targetType": "group", "id": "all_users", ...}].
const allUsersTargetID = "all_users"

// Detect checks if FIDO2 is enabled tenant-wide, not just enabled on the
// policy object while actually scoped to a subset of users.
//
// State=="enabled" alone is not sufficient: FIDO2's own includeTargets can
// restrict the method to a specific group rather than all_users, in which
// case the tenant-level toggle being "enabled" says nothing about whether
// most users actually have FIDO2 available. That includeTargets list is
// already collected (types.AuthMethodConfig.IncludeTargets, populated by
// internal/providers/azure/client.go's decodeAuthMethodTargets), so this
// detector now checks it directly instead of trusting State alone.
func (d *NoFIDO2Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDNoFIDO2,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryNoFIDO2),
		Title:       "FIDO2 Security Keys Not Enabled Tenant-Wide",
		Description: "FIDO2 security keys are not enabled for all users. FIDO2 provides phishing-resistant authentication. A tenant-wide toggle without all_users coverage in includeTargets leaves most users without FIDO2 available.",
		Count:       0,
	}

	if data.AzureAuthMethodsPolicy == nil {
		return []types.Finding{finding}
	}

	fido2 := data.AzureAuthMethodsPolicy.FIDO2
	coversAllUsers := false
	for _, target := range fido2.IncludeTargets {
		if target.ID == allUsersTargetID {
			coversAllUsers = true
			break
		}
	}

	if fido2.State != "enabled" || !coversAllUsers {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMfaNoFido2Detector())
}
