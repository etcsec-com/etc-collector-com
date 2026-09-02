package mfa

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	ID       = "MFA_NOT_ENFORCED_ADMINS"
	Category = audit.CategoryIdentity
)

// MfaNotEnforcedAdminsDetector checks if MFA is enforced for administrators
type MfaNotEnforcedAdminsDetector struct {
	audit.BaseDetector
}

// NewMfaNotEnforcedAdminsDetector creates a new MFA not enforced for admins detector
func NewMfaNotEnforcedAdminsDetector() *MfaNotEnforcedAdminsDetector {
	return &MfaNotEnforcedAdminsDetector{
		BaseDetector: audit.NewBaseDetector(ID, Category),
	}
}

// Detect checks if any Conditional Access policy enforces MFA for admin roles
func (d *MfaNotEnforcedAdminsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        ID,
		Severity:    types.SeverityCritical,
		Category:    string(Category),
		Title:       "MFA Not Enforced for Administrators",
		Description: "No Conditional Access policy requires MFA for directory roles. Administrative accounts without MFA are prime targets for credential attacks.",
		Count:       0,
	}

	// Check if any enabled CA policy requires MFA for admin roles
	hasMFAForAdmins := false
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}

		// Check if policy targets admin roles
		targetsAdmins := len(policy.IncludeRoles) > 0

		// Check if policy grants MFA
		requiresMFA := false
		for _, control := range policy.GrantControls {
			if control == "mfa" {
				requiresMFA = true
				break
			}
		}

		if targetsAdmins && requiresMFA {
			hasMFAForAdmins = true
			break
		}
	}

	if !hasMFAForAdmins {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMfaNotEnforcedAdminsDetector())
}
