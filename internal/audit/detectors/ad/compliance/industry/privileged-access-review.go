package industry

import (
	"context"
	"strconv"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PrivilegedAccessReviewDetector checks for privileged access review compliance
type PrivilegedAccessReviewDetector struct {
	audit.BaseDetector
}

// NewPrivilegedAccessReviewDetector creates a new detector
func NewPrivilegedAccessReviewDetector() *PrivilegedAccessReviewDetector {
	return &PrivilegedAccessReviewDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGED_ACCESS_REVIEW_MISSING", audit.CategoryCompliance),
	}
}

// Detect executes the detection
//
// Fixed three real defects, all confirmed against the lab domain (2 DCs):
//  1. lastLogon is a per-DC, non-replicated attribute - comparing against
//     whichever DC this collector happened to query undercounts activity
//     that occurred on OTHER domain controllers, producing false "stale"
//     positives in any multi-DC domain. lastLogonTimestamp IS replicated
//     (with an up-to ~14-day lag) and is the attribute Microsoft documents
//     for cross-DC staleness checks. Now compares against whichever of the
//     two is more recent.
//  2. isAdmin matched the bare substring "administrators", which also
//     matches role-scoped Builtin groups carrying no domain-wide privilege
//     - "Hyper-V Administrators", "DHCP Administrators", "Storage Replica
//     Administrators" - producing false positives. Now matched only against
//     the DN's leading CN component, so only the literal
//     BUILTIN\Administrators group counts.
//  3. Accounts that have NEVER logged on (both attributes zero) were
//     explicitly excluded - but a privileged account created and never used
//     is at least as much a review candidate as one that went stale, if not
//     more (an unused standing credential nobody has ever needed). The zero
//     time value naturally compares Before() any real staleThreshold, so
//     dropping the explicit exclusion includes it without special-casing.
func (d *PrivilegedAccessReviewDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var staleAdmins []string
	now := data.Now
	staleThreshold := now.AddDate(0, 0, -90) // 90 days

	// Check for stale privileged accounts
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}

		if !isPrivilegedGroupMember(u.MemberOf) {
			continue
		}

		lastActivity := u.LastLogon
		if u.LastLogonTimestamp.After(lastActivity) {
			lastActivity = u.LastLogonTimestamp
		}

		if lastActivity.Before(staleThreshold) {
			staleAdmins = append(staleAdmins, u.SAMAccountName)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Privileged Access Review Required",
		Description: "Regular review of privileged access is required for compliance. Some privileged accounts show signs of inactivity.",
		Count:       0,
		Details: map[string]interface{}{
			"category":    "Industry Best Practices",
			"staleAdmins": len(staleAdmins),
			"threshold":   "90 days without activity (lastLogon or lastLogonTimestamp, whichever is more recent), including accounts that have never logged on",
		},
	}

	if len(staleAdmins) > 0 {
		finding.Count = len(staleAdmins)
		if len(staleAdmins) <= 10 {
			finding.Details["staleAdminAccounts"] = staleAdmins
		} else {
			finding.Details["staleAdminAccounts"] = staleAdmins[:10]
			finding.Details["note"] = "Showing first 10 of " + strconv.Itoa(len(staleAdmins)) + " stale admin accounts"
		}
		finding.Details["recommendations"] = []string{
			"Review privileged access quarterly",
			"Remove or disable inactive admin accounts",
			"Implement privileged access management (PAM)",
			"Use just-in-time privileged access where possible",
		}
	}

	return []types.Finding{finding}
}

// isPrivilegedGroupMember reports whether memberOf contains one of the
// canonical highly-privileged AD groups. "Domain Admins"/"Enterprise
// Admins"/"Schema Admins" are matched as substrings, safe because no other
// real AD group name contains them. "Administrators" is deliberately NOT
// matched as a bare substring (see the comment on Detect above) - only the
// DN's leading CN component is compared, so only the literal
// BUILTIN\Administrators group counts, not role-scoped lookalikes such as
// "Hyper-V Administrators".
func isPrivilegedGroupMember(memberOf []string) bool {
	for _, dn := range memberOf {
		lower := strings.ToLower(dn)
		if strings.Contains(lower, "domain admins") ||
			strings.Contains(lower, "enterprise admins") ||
			strings.Contains(lower, "schema admins") {
			return true
		}
		if strings.EqualFold(leadingCN(dn), "administrators") {
			return true
		}
	}
	return false
}

// leadingCN extracts the value of a DN's first RDN when it is a CN=
// component (e.g. "CN=Administrators,CN=Builtin,DC=example,DC=com" ->
// "Administrators"). Returns "" if the DN doesn't start with "CN=".
func leadingCN(dn string) string {
	const prefix = "cn="
	if len(dn) < len(prefix) || strings.ToLower(dn[:len(prefix)]) != prefix {
		return ""
	}
	rest := dn[len(prefix):]
	if idx := strings.Index(rest, ","); idx >= 0 {
		return rest[:idx]
	}
	return rest
}

func init() {
	audit.MustRegister(NewPrivilegedAccessReviewDetector())
}
