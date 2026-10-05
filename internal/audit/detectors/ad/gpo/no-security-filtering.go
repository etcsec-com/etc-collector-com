package gpo

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NoSecurityFilteringDetector checks for GPOs without security filtering
type NoSecurityFilteringDetector struct {
	audit.BaseDetector
}

// NewNoSecurityFilteringDetector creates a new detector
func NewNoSecurityFilteringDetector() *NoSecurityFilteringDetector {
	return &NoSecurityFilteringDetector{
		BaseDetector: audit.NewBaseDetector("GPO_NO_SECURITY_FILTERING", audit.CategoryGPO),
	}
}

const (
	sidEveryone        = "S-1-1-0"
	sidDomainComputers = "-515" // Suffix
)

// Detect executes the detection
func (d *NoSecurityFilteringDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.GPO

	// Get linked GPO GUIDs
	linkedGuids := make(map[string]bool)
	for _, link := range data.GPOLinks {
		if link.LinkEnabled {
			linkedGuids[strings.ToLower(link.GPOCN)] = true
		}
	}

	for _, gpo := range data.GPOs {
		// Only check linked GPOs
		if !linkedGuids[strings.ToLower(gpo.CN)] {
			continue
		}

		// Get ACLs for this GPO
		hasUnrestrictedApply := false
		hasSpecificFiltering := false

		for _, acl := range data.GPOAcls {
			if !strings.EqualFold(acl.GPODN, gpo.DistinguishedName) {
				continue
			}

			if (acl.AccessMask & applyGroupPolicyRight) == 0 {
				continue
			}

			// Check for unrestricted apply
			if acl.Trustee == sidAuthenticatedUsers || acl.Trustee == sidEveryone {
				hasUnrestrictedApply = true
			} else if !strings.HasSuffix(acl.Trustee, sidDomainComputers) {
				// Specific group filtering
				hasSpecificFiltering = true
			}
		}

		// No filtering if auth users/everyone can apply and no specific groups defined
		if hasUnrestrictedApply && !hasSpecificFiltering {
			affected = append(affected, gpo)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "GPO Without Security Filtering",
		Description: "GPOs that apply to all Authenticated Users or Everyone without specific security filtering. Consider restricting GPO application to specific groups.",
		Count:       len(affected),
	}

	if len(affected) > 0 {
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedGPOEntities(affected)
		}
		finding.Details = map[string]interface{}{
			"recommendation": "Apply security filtering to restrict GPO application to specific groups.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNoSecurityFilteringDetector())
}
