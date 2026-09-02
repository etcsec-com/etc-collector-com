package industry

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// VendorAccountUnmonitoredDetector checks for unmonitored vendor accounts
type VendorAccountUnmonitoredDetector struct {
	audit.BaseDetector
}

// NewVendorAccountUnmonitoredDetector creates a new detector
func NewVendorAccountUnmonitoredDetector() *VendorAccountUnmonitoredDetector {
	return &VendorAccountUnmonitoredDetector{
		BaseDetector: audit.NewBaseDetector("VENDOR_ACCOUNT_UNMONITORED", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *VendorAccountUnmonitoredDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var potentialVendorAccounts []types.User

	// Common patterns for vendor/external accounts
	vendorPatterns := []string{
		"vendor", "contractor", "external", "consultant",
		"partner", "supplier", "third-party", "3rdparty",
		"temp", "temporary", "service",
	}

	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}

		nameLower := strings.ToLower(u.SAMAccountName)
		descLower := strings.ToLower(u.Description)

		for _, pattern := range vendorPatterns {
			if strings.Contains(nameLower, pattern) || strings.Contains(descLower, pattern) {
				potentialVendorAccounts = append(potentialVendorAccounts, u)
				break
			}
		}
	}

	// Extract account names for details (backward-compatible)
	accountNames := make([]string, len(potentialVendorAccounts))
	for i, u := range potentialVendorAccounts {
		accountNames[i] = u.SAMAccountName
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Vendor Account Monitoring Review",
		Description: "Potential vendor/external accounts detected. Ensure these accounts are properly monitored and have limited access.",
		Count:       0,
		Details: map[string]interface{}{
			"category":                "Industry Best Practices",
			"potentialVendorAccounts": len(potentialVendorAccounts),
		},
	}

	if len(potentialVendorAccounts) > 0 {
		finding.Count = len(potentialVendorAccounts)
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedUserEntities(potentialVendorAccounts)
		}
		if len(accountNames) <= 20 {
			finding.Details["accounts"] = accountNames
		} else {
			finding.Details["accounts"] = accountNames[:20]
			finding.Details["note"] = "Showing first 20 potential vendor accounts"
		}
		finding.Details["recommendations"] = []string{
			"Implement separate OU for vendor accounts",
			"Set account expiration dates for all vendor accounts",
			"Enable enhanced auditing for vendor account activities",
			"Review vendor access quarterly",
			"Use separate admin accounts for vendor support staff",
			"Implement just-in-time access for vendor accounts",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewVendorAccountUnmonitoredDetector())
}
