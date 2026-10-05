package membership

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DnsAdminsMemberDetector checks for DnsAdmins membership
type DnsAdminsMemberDetector struct {
	audit.BaseDetector
}

// NewDnsAdminsMemberDetector creates a new detector
func NewDnsAdminsMemberDetector() *DnsAdminsMemberDetector {
	return &DnsAdminsMemberDetector{
		BaseDetector: audit.NewBaseDetector("DNS_ADMINS_MEMBER", audit.CategoryGroups),
	}
}

// dnsAdminsGroupDNs returns the lowercased DN of every collected group whose
// sAMAccountName equals "DnsAdmins" (case-insensitive). sAMAccountName, not
// CN, is what identifies the real group: "The logon name must be 20 or
// fewer characters long and be unique among all security principal objects
// within the domain." (Microsoft, "User Naming Attributes" -
// learn.microsoft.com/en-us/windows/win32/ad/naming-properties, section
// sAMAccountName). A group's CN carries no such guarantee - any object
// anywhere in the domain can be created with the same CN as another,
// regardless of container.
//
// DnsAdmins has NO well-known/fixed RID suffix: it is created by the DNS
// Server role installation with a RID assigned at creation time, which
// varies per forest - unlike Domain Admins (-512) or Backup Operators
// (-551), it cannot be resolved through privgroups.DNsBySIDSuffix.
// sAMAccountName is therefore the non-localized identifier available for
// this one group; it carries a declared, accepted limitation - a DnsAdmins
// group renamed on a non-English or customized forest is NOT recognized by
// this detector, since its sAMAccountName would then differ too. Other
// detectors (e.g. kerberos/kerberoasting-risk.go) read data.Tier0Config,
// loaded from an operator-provided tier0_groups.yaml, to let a rename be
// declared explicitly; this detector does NOT consult that config today, so
// it carries no such recourse - adding one is future work, not something
// this comment should claim already exists.
//
// If no group with this sAMAccountName was collected, the returned set is
// empty and every membership check below fails: the detector fails CLOSED
// (under-detection, never a false positive) rather than falling back to any
// CN-based heuristic.
func dnsAdminsGroupDNs(groups []types.Group) map[string]bool {
	dns := make(map[string]bool)
	for _, g := range groups {
		if strings.EqualFold(g.SAMAccountName, "DnsAdmins") {
			dns[strings.ToLower(g.DN)] = true
		}
	}
	return dns
}

// isMemberOfDnsAdmins reports whether any DN in memberOf, compared
// case-insensitively, is in dnsAdminsDNs (as built by dnsAdminsGroupDNs).
// Direct membership only, same scope as the code this replaces: no nested
// or transitive group membership is considered.
func isMemberOfDnsAdmins(memberOf []string, dnsAdminsDNs map[string]bool) bool {
	for _, dn := range memberOf {
		if dnsAdminsDNs[strings.ToLower(dn)] {
			return true
		}
	}
	return false
}

// Detect executes the detection
func (d *DnsAdminsMemberDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	dnsAdminsDNs := dnsAdminsGroupDNs(data.Groups)

	var affected []types.User
	for _, user := range data.Users {
		if isMemberOfDnsAdmins(user.MemberOf, dnsAdminsDNs) {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "DnsAdmins Member",
		Description: "Users in DnsAdmins group. Can load arbitrary DLLs on domain controllers (escalation to Domain Admin).",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDnsAdminsMemberDetector())
}
