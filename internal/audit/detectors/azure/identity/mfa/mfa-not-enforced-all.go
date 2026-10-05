package mfa

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDAll       = "MFA_NOT_ENFORCED_ALL"
	CategoryAll = audit.CategoryIdentity
)

// AllUsersDetector checks if MFA is enforced for all users
type AllUsersDetector struct {
	audit.BaseDetector
}

// NewMfaNotEnforcedAllDetector creates a new MFA not enforced for all users detector
func NewMfaNotEnforcedAllDetector() *AllUsersDetector {
	return &AllUsersDetector{
		BaseDetector: audit.NewBaseDetector(IDAll, CategoryAll),
	}
}

// Detect checks if any Conditional Access policy enforces MFA for all users
func (d *AllUsersDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDAll,
		Severity:    types.SeverityCritical,
		Category:    string(CategoryAll),
		Title:       "MFA Not Enforced for All Users",
		Description: "No Conditional Access policy requires MFA for all users. MFA blocks 99.9% of automated attacks.",
		Count:       0,
	}

	// Check if any enabled CA policy requires MFA for all users
	hasMFAForAll := false
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}

		// Check if policy targets all users
		targetsAll := false
		for _, user := range policy.IncludeUsers {
			if user == "All" {
				targetsAll = true
				break
			}
		}

		// Check if policy grants MFA
		requiresMFA := false
		for _, control := range policy.GrantControls {
			if control == "mfa" {
				requiresMFA = true
				break
			}
		}

		if targetsAll && requiresMFA {
			hasMFAForAll = true
			break
		}
	}

	if !hasMFAForAll {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewMfaNotEnforcedAllDetector())
}
