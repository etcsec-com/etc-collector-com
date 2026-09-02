package serviceaccounts

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// NamingDetector detects service accounts by naming convention
type NamingDetector struct {
	audit.BaseDetector
}

// NewNamingDetector creates a new detector
func NewNamingDetector() *NamingDetector {
	return &NamingDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_NAMING", audit.CategoryAccounts),
	}
}

var namingPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^svc_`),
	regexp.MustCompile(`(?i)_svc$`),
	regexp.MustCompile(`(?i)service`),
	regexp.MustCompile(`(?i)^sa_`),
	regexp.MustCompile(`(?i)_sa$`),
}

// Detect executes the detection
func (d *NamingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Exclude accounts with SPN (covered by SERVICE_ACCOUNT_WITH_SPN)
		if len(u.ServicePrincipalNames) > 0 {
			continue
		}
		// Exclude disabled accounts
		if u.Disabled {
			continue
		}

		// Check naming patterns
		for _, pattern := range namingPatterns {
			if pattern.MatchString(u.SAMAccountName) {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Service Account by Naming Convention",
		Description: "User accounts matching service account naming patterns (svc_, _svc, service, etc.) without SPN. Review if these are actual service accounts.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewNamingDetector())
}
