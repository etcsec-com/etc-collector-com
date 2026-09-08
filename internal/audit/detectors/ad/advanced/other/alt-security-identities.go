package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AltSecurityIdentitiesDetector detects privileged accounts with altSecurityIdentities configured
type AltSecurityIdentitiesDetector struct {
	audit.BaseDetector
}

// NewAltSecurityIdentitiesDetector creates a new detector
func NewAltSecurityIdentitiesDetector() *AltSecurityIdentitiesDetector {
	return &AltSecurityIdentitiesDetector{
		BaseDetector: audit.NewBaseDetector("ALT_SECURITY_IDENTITIES", audit.CategoryAdvanced),
	}
}

// Detect executes the detection.
//
// Source: Microsoft Support KB5014754, "Certificate-based authentication
// changes on Windows domain controllers" - "Certificate mappings" section
// (support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16).
// altSecurityIdentities supports six mapping types; three are weak
// (X509IssuerSubject, X509SubjectOnly, X509RFC822 - based on reusable
// identifiers like usernames/emails) and three are strong
// (X509IssuerSerialNumber, X509SKI, X509SHA1PublicKey). This detector
// flags any non-empty altSecurityIdentities value on a privileged account,
// not just the weak mapping types - broader than what KB5014754 calls
// exploitable, but defensible as an attack-surface signal: a strong
// mapping is a legitimate credential trust relationship, still worth an
// admin's awareness. IsInAnyGroup below only resolves direct memberOf, not
// nested group membership (helpers/entities.go, shared across detectors).
func (d *AltSecurityIdentitiesDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if len(user.AltSecurityIdentities) == 0 {
			continue
		}

		if helpers.IsInAnyGroup(user.MemberOf, helpers.AdminGroups) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Privileged Accounts with altSecurityIdentities Configured",
		Description: "Privileged accounts have the altSecurityIdentities attribute configured, which maps external credentials (certificates, Kerberos principals) to AD accounts. This can be exploited for certificate-based impersonation attacks.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAltSecurityIdentitiesDetector())
}
