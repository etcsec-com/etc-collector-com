package advanced

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/detectors/ad/privgroups"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DangerousBuiltinMembershipDetector detects accounts in dangerous built-in groups
type DangerousBuiltinMembershipDetector struct {
	audit.BaseDetector
}

// NewDangerousBuiltinMembershipDetector creates a new detector
func NewDangerousBuiltinMembershipDetector() *DangerousBuiltinMembershipDetector {
	return &DangerousBuiltinMembershipDetector{
		BaseDetector: audit.NewBaseDetector("DANGEROUS_BUILTIN_MEMBERSHIP", audit.CategoryAccounts),
	}
}

// dangerousBuiltinGroups is the single (name, RID suffix) table this
// detector uses for BOTH detection and the Details output below: the two
// used to be separate parallel lists (a name-only slice for
// Details["dangerousGroups"], a suffix-only slice for detection) kept in
// sync only by hand, with nothing to catch them drifting apart. Matched by
// SID, not by CN, so a group homonym with no real membership in these
// built-ins cannot false-positive, and a real built-in renamed on a
// non-English forest is still caught. Same 15 groups, unchanged. Suffixes
// read from Microsoft Learn "Security Identifiers"
// (learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/
// understand-security-identifiers); the 13 S-1-5-32-* entries also appear in
// this package's own wellKnownSIDs table (internal/audit/wellknown_sids.go),
// sourced from the same page. Cert Publishers and RAS and IAS Servers are
// domain-relative RIDs (S-1-5-<domain>-517 / -553), not S-1-5-32-*.
var dangerousBuiltinGroups = []struct {
	Name   string
	Suffix string
}{
	{"Cert Publishers", "-517"},
	{"RAS and IAS Servers", "-553"},
	{"Windows Authorization Access Group", "-560"},
	{"Terminal Server License Servers", "-561"},
	{"Incoming Forest Trust Builders", "-557"},
	{"Performance Log Users", "-559"},
	{"Performance Monitor Users", "-558"},
	{"Distributed COM Users", "-562"},
	{"Remote Desktop Users", "-555"},
	{"Network Configuration Operators", "-556"},
	{"Cryptographic Operators", "-569"},
	{"Event Log Readers", "-573"},
	{"Hyper-V Administrators", "-578"},
	{"Access Control Assistance Operators", "-579"},
	{"Remote Management Users", "-580"},
}

// dangerousBuiltinGroupNames returns dangerousBuiltinGroups' Name column, in
// table order - the exact value Details["dangerousGroups"] carried before
// this table merge (same 15 names, same order, same []string type).
func dangerousBuiltinGroupNames() []string {
	names := make([]string, len(dangerousBuiltinGroups))
	for i, g := range dangerousBuiltinGroups {
		names[i] = g.Name
	}
	return names
}

// dangerousBuiltinGroupSuffixes returns dangerousBuiltinGroups' Suffix
// column, in table order - the exact value dangerousGroupSIDSuffixes
// carried before this table merge.
func dangerousBuiltinGroupSuffixes() []string {
	suffixes := make([]string, len(dangerousBuiltinGroups))
	for i, g := range dangerousBuiltinGroups {
		suffixes[i] = g.Suffix
	}
	return suffixes
}

// Detect executes the detection
func (d *DangerousBuiltinMembershipDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	dangerousDNs := privgroups.DNsBySIDSuffix(data, dangerousBuiltinGroupSuffixes())

	for _, u := range data.Users {
		if u.Disabled || len(u.MemberOf) == 0 {
			continue
		}

		if privgroups.IsMemberOfAny(u.MemberOf, dangerousDNs) {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Dangerous Built-in Group Membership",
		Description: "User accounts with membership in overlooked but dangerous built-in groups. These groups grant elevated privileges that may allow privilege escalation.",
		Count:       len(affected),
	}

	if data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
		finding.Details = map[string]interface{}{
			"dangerousGroups": dangerousBuiltinGroupNames(),
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousBuiltinMembershipDetector())
}
