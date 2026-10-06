package serviceaccounts

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrivilegedDetector detects service accounts in privileged groups
type PrivilegedDetector struct {
	audit.BaseDetector
}

// NewPrivilegedDetector creates a new detector
func NewPrivilegedDetector() *PrivilegedDetector {
	return &PrivilegedDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_PRIVILEGED", audit.CategoryAccounts),
	}
}

// Detect executes the detection.
//
// Group membership used to be matched by testing whether a memberOf DN
// contained "CN=<English group name>" as a raw substring. That is both too
// narrow (a domain with localized/renamed built-in groups, e.g. French
// "Admins du domaine", never matches an English string) and imprecise (a
// group merely named "Domain AdminsX" would also match). Privileged groups
// are matched instead by their well-known RID suffix
// (types.PrivilegedSIDSuffixes, via audit.IsBuiltinAdminTrustee) resolved
// from data.Groups - the same SID a renamed or localized group still
// carries. This only sees direct memberOf entries, not nested group
// membership or primaryGroupID.
func (d *PrivilegedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	groupSIDByDN := make(map[string]string, len(data.Groups))
	for _, g := range data.Groups {
		if g.DN != "" && g.ObjectSID != "" {
			groupSIDByDN[strings.ToLower(g.DN)] = g.ObjectSID
		}
	}

	var affected []types.User

	for _, u := range data.Users {
		// Must be a service account
		if !isServiceAccount(u) {
			continue
		}
		// Must be enabled
		if u.Disabled {
			continue
		}
		// Check if in privileged groups
		if len(u.MemberOf) == 0 {
			continue
		}

		for _, dn := range u.MemberOf {
			sid, ok := groupSIDByDN[strings.ToLower(dn)]
			if !ok {
				continue
			}
			if audit.IsBuiltinAdminTrustee(sid) {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Service Account in Privileged Group",
		Description: "Service accounts with membership in privileged groups (Domain Admins, etc.). If compromised, attackers gain full domain control.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"recommendation": "Remove service accounts from privileged groups. Grant only the minimum permissions needed for the service to function.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPrivilegedDetector())
}
