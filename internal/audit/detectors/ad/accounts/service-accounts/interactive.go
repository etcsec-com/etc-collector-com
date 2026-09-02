package serviceaccounts

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// InteractiveDetector detects service accounts with interactive logon
type InteractiveDetector struct {
	audit.BaseDetector
}

// NewInteractiveDetector creates a new detector
func NewInteractiveDetector() *InteractiveDetector {
	return &InteractiveDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_INTERACTIVE", audit.CategoryAccounts),
	}
}

var servicePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^svc[_-]`),
	regexp.MustCompile(`(?i)^sa[_-]`),
	regexp.MustCompile(`(?i)service`),
	regexp.MustCompile(`(?i)^sql`),
	regexp.MustCompile(`(?i)^iis`),
	regexp.MustCompile(`(?i)^app`),
}

// Detect executes the detection
func (d *InteractiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	now := data.Now
	thirtyDaysAgo := now.AddDate(0, 0, -30)

	for _, u := range data.Users {
		// Must be enabled
		if u.Disabled {
			continue
		}

		// Must be a service account (has SPN or matches naming pattern)
		hasSPN := len(u.ServicePrincipalNames) > 0
		matchesPattern := false
		for _, pattern := range servicePatterns {
			if pattern.MatchString(u.SAMAccountName) {
				matchesPattern = true
				break
			}
		}

		if !hasSPN && !matchesPattern {
			continue
		}

		// Check if logged on in last 30 days (may be used interactively)
		if !u.LastLogon.IsZero() && u.LastLogon.After(thirtyDaysAgo) {
			affected = append(affected, u)
			continue
		}

		// Check for risky flags
		pwdNeverExpires := (u.UserAccountControl & types.UACDontExpirePassword) != 0
		notDelegated := (u.UserAccountControl & types.UACNotDelegated) != 0

		if pwdNeverExpires && !notDelegated {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Service Account with Interactive Logon",
		Description: "Service accounts appear to allow or use interactive logon. Service accounts should be restricted to service-only authentication.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Apply 'Deny log on locally' and 'Deny log on through Remote Desktop Services' rights. Use gMSA where possible.",
			"risks": []string{
				"Interactive sessions leave credentials in memory (mimikatz target)",
				"Increases attack surface for credential theft",
				"May indicate misuse of service accounts",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInteractiveDetector())
}
