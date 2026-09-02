package legacyauth

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	ID       = "LEGACY_AUTH_ALLOWED"
	Category = audit.CategoryIdentity
)

// LegacyAuthAllowedDetector checks if legacy authentication protocols are allowed
type LegacyAuthAllowedDetector struct {
	audit.BaseDetector
}

// NewLegacyAuthAllowedDetector creates a new legacy auth allowed detector
func NewLegacyAuthAllowedDetector() *LegacyAuthAllowedDetector {
	return &LegacyAuthAllowedDetector{
		BaseDetector: audit.NewBaseDetector(ID, Category),
	}
}

// Detect checks if any CA policy blocks legacy authentication protocols
func (d *LegacyAuthAllowedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        ID,
		Severity:    types.SeverityCritical,
		Category:    string(Category),
		Title:       "Legacy Authentication Protocols Allowed",
		Description: "No Conditional Access policy blocks legacy authentication protocols (POP, IMAP, SMTP). Legacy protocols cannot use MFA.",
		Count:       0,
	}

	// Check if any enabled CA policy blocks legacy auth
	hasLegacyAuthBlock := false
	for _, policy := range data.AzureConditionalAccessPolicies {
		if policy.State != "enabled" {
			continue
		}

		// Check if policy targets legacy auth client apps
		targetsLegacyAuth := false
		for _, appType := range policy.ClientAppTypes {
			if appType == "exchangeActiveSync" || appType == "other" {
				targetsLegacyAuth = true
				break
			}
		}

		// Check if policy blocks access
		blocksAccess := false
		for _, control := range policy.GrantControls {
			if control == "block" {
				blocksAccess = true
				break
			}
		}

		if targetsLegacyAuth && blocksAccess {
			hasLegacyAuthBlock = true
			break
		}
	}

	if !hasLegacyAuthBlock {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLegacyAuthAllowedDetector())
}
