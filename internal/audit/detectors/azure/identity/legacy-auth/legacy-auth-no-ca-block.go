package legacyauth

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDNoCABlock       = "LEGACY_AUTH_NO_CA_BLOCK"
	CategoryNoCABlock = audit.CategoryIdentity
)

// NoCABlockDetector checks if there is a CA policy that blocks legacy auth
type NoCABlockDetector struct {
	audit.BaseDetector
}

// NewLegacyAuthNoCABlockDetector creates a new no CA block detector
func NewLegacyAuthNoCABlockDetector() *NoCABlockDetector {
	return &NoCABlockDetector{
		BaseDetector: audit.NewBaseDetector(IDNoCABlock, CategoryNoCABlock),
	}
}

// Detect checks if any CA policy explicitly blocks legacy authentication for all users
func (d *NoCABlockDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDNoCABlock,
		Severity:    types.SeverityHigh,
		Category:    string(CategoryNoCABlock),
		Title:       "No Conditional Access Policy Blocks Legacy Auth",
		Description: "No Conditional Access policy explicitly blocks legacy authentication for all users.",
		Count:       0,
	}

	// Check for a blocking CA policy with block grant control
	hasBlockingPolicy := false
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

		// Check if policy targets legacy auth
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

		if targetsAll && targetsLegacyAuth && blocksAccess {
			hasBlockingPolicy = true
			break
		}
	}

	if !hasBlockingPolicy {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLegacyAuthNoCABlockDetector())
}
