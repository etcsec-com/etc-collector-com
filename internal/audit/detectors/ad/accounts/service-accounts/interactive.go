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

// Detect executes the detection.
//
// This detector cannot observe logon TYPE: LDAP exposes lastLogon (bumped
// on any bind - service, network, or interactive alike, and not
// replicated between DCs) but nothing equivalent to a Windows security
// event's logon-type field. The former title/description claimed to
// detect "interactive logon" specifically, which nothing here measures.
// Reworded to state the actual, weaker signal: recent authentication
// activity on an account that looks like a service account, worth a
// human glance, not proof of interactive use. The former second branch
// (pwdNeverExpires && !notDelegated) is dropped entirely: those UAC flags
// say nothing about logon type either - they were general risk posture
// flags dressed up as "interactivity" evidence, and password-never-expires
// with real coverage of that risk exists as its own detector.
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

		// Recently authenticated: a weak proxy for possible interactive use,
		// not evidence of it.
		if !u.LastLogon.IsZero() && u.LastLogon.After(thirtyDaysAgo) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Service Account With Recent Authentication Activity",
		Description: "Accounts that look like service accounts (SPN or naming pattern) authenticated within the last 30 days. lastLogon does not distinguish service, network, or interactive binds and is not replicated between domain controllers, so this is a review signal, not proof of interactive logon.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Confirm with the service owner whether the account is used interactively. If so, apply 'Deny log on locally' / 'Deny log on through Remote Desktop Services' and migrate to a gMSA where possible.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInteractiveDetector())
}
