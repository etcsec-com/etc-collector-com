package privileged

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DomainAdminDescriptionDetector detects sensitive terms in description
//
// Disabled accounts are excluded here: UF_ACCOUNTDISABLE blocks
// authentication for this account across every protocol (interactive logon,
// LDAP bind, NTLM, Kerberos), so a keyword revealing this account's
// privileged status cannot be leveraged to target it today - there is no
// active session to compromise. The exposure itself does not go away - the
// description text is still readable on the object by anyone who can read
// the attribute - which is why it stays reported, at Low, by
// DomainAdminInDescriptionOnDisabledAccountDetector (see
// domain-admin-description-on-disabled-account.go): it would matter again
// the moment the account is re-enabled.
type DomainAdminDescriptionDetector struct {
	audit.BaseDetector
}

// NewDomainAdminDescriptionDetector creates a new detector
func NewDomainAdminDescriptionDetector() *DomainAdminDescriptionDetector {
	return &DomainAdminDescriptionDetector{
		BaseDetector: audit.NewBaseDetector("DOMAIN_ADMIN_IN_DESCRIPTION", audit.CategoryAccounts),
	}
}

var sensitiveKeywords = []*regexp.Regexp{
	regexp.MustCompile(`(?i)domain\s*admin`),
	regexp.MustCompile(`(?i)enterprise\s*admin`),
	regexp.MustCompile(`(?i)administrator`),
	regexp.MustCompile(`(?i)admin\s*account`),
	regexp.MustCompile(`(?i)privileged`),
}

// Detect executes the detection
func (d *DomainAdminDescriptionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if u.Disabled {
			continue
		}
		if u.Description == "" {
			continue
		}

		for _, pattern := range sensitiveKeywords {
			if pattern.MatchString(u.Description) {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Sensitive Terms in Description",
		Description: "User accounts with admin/privileged keywords in description field. Information disclosure.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDomainAdminDescriptionDetector())
}
