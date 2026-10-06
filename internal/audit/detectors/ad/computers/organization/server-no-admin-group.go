package organization

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ServerNoAdminGroupDetector detects servers without managed admin groups
type ServerNoAdminGroupDetector struct {
	audit.BaseDetector
}

// NewServerNoAdminGroupDetector creates a new detector
func NewServerNoAdminGroupDetector() *ServerNoAdminGroupDetector {
	return &ServerNoAdminGroupDetector{
		BaseDetector: audit.NewBaseDetector("SERVER_NO_ADMIN_GROUP", audit.CategoryComputers),
	}
}

var serverPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)server`),
	regexp.MustCompile(`(?i)^srv`),
	regexp.MustCompile(`(?i)^sql`),
	regexp.MustCompile(`(?i)^web`),
	regexp.MustCompile(`(?i)^app`),
	regexp.MustCompile(`(?i)^db`),
	regexp.MustCompile(`(?i)^file`),
}

// builtinAdministratorsSID is the well-known SID for the local
// BUILTIN\Administrators group - the group a per-server "managed admin
// group" convention (e.g. SRV01-Admins nested into local Administrators via
// a GPO Restricted Groups / Group Policy Preferences setting) actually
// controls.
const builtinAdministratorsSID = "S-1-5-32-544"

// Detect executes the detection
func (d *ServerNoAdminGroupDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Server Without Managed Admin Group",
		Description: "Servers whose local Administrators group membership is not pinned by any GPO Restricted Groups / Group Policy Preferences setting. Local admin access can accumulate uncontrolled instead of being managed through a documented group (e.g. SRV01-Admins).",
	}

	// Whether a server's local Administrators membership is "managed" can
	// only be answered from SYSVOL-parsed GPO data (GptTmpl.inf
	// [Group Membership] / Restricted Groups) - the previous
	// Description-keyword check ("unmanaged"/"legacy"/"deprecated") measured
	// nothing about admin-group management and stayed empty on any domain
	// with unset Description fields, which is most domains. Without parsed
	// GPO policy data we cannot tell managed from unmanaged either, so skip
	// rather than flag every server as unmanaged - same reasoning ANSSI M29
	// uses for the identical data gap (compliance/anssi/m29_local_admin.go).
	if len(data.GPOPolicies) == 0 {
		return []types.Finding{finding}
	}

	managedDNs := computersWithManagedAdminGroup(data)

	var affected []types.Computer
	for _, c := range data.Computers {
		if !c.Enabled() {
			continue
		}
		if !isServerComputer(c) {
			continue
		}
		if managedDNs[strings.ToLower(c.DN)] {
			continue
		}
		affected = append(affected, c)
	}

	finding.Count = len(affected)

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}
	if len(affected) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Create dedicated admin groups for each server (e.g., SRV01-Admins) and manage local Administrators membership via GPO Restricted Groups.",
			"risks": []string{
				"Unknown administrators may have access",
				"Audit trail for admin actions may be incomplete",
				"Compliance violations for access management",
			},
		}
	}

	return []types.Finding{finding}
}

// isServerComputer reports whether a computer looks like a server, by
// SAMAccountName convention or its collected OperatingSystem string.
func isServerComputer(c types.Computer) bool {
	for _, pattern := range serverPatterns {
		if pattern.MatchString(c.SAMAccountName) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(c.OperatingSystem), "server")
}

// computersWithManagedAdminGroup returns the set of computer DNs (lowercased)
// covered by at least one GPO that pins local BUILTIN\Administrators
// membership to an explicit, non-empty set of members (a GPO Restricted
// Groups / Group Policy Preferences "managed admin group" setting) via an
// enabled link reaching that computer's OU (or the domain root).
func computersWithManagedAdminGroup(data *audit.DetectorData) map[string]bool {
	managingGUIDs := make(map[string]bool)
	for guid, p := range data.GPOPolicies {
		if p == nil {
			continue
		}
		for _, rg := range p.RestrictedGroups {
			if isBuiltinAdministratorsPrincipal(rg.GroupSID, rg.GroupName) && len(rg.MembersSIDs) > 0 {
				managingGUIDs[normalizeOrgGUID(guid)] = true
				break
			}
		}
	}
	if len(managingGUIDs) == 0 {
		return nil
	}

	var managingContainers []string
	for _, l := range data.GPOLinks {
		if !l.LinkEnabled {
			continue
		}
		if managingGUIDs[normalizeOrgGUID(l.GPOCN)] || (l.GPOGuid != "" && managingGUIDs[normalizeOrgGUID(l.GPOGuid)]) {
			managingContainers = append(managingContainers, l.LinkedTo)
		}
	}
	if len(managingContainers) == 0 {
		return nil
	}

	managed := make(map[string]bool)
	for _, c := range data.Computers {
		for _, container := range managingContainers {
			u := strings.ToUpper(strings.TrimSpace(container))
			if strings.HasPrefix(u, "DC=") || dnUnderOrEqual(c.DN, container) {
				managed[strings.ToLower(c.DN)] = true
				break
			}
		}
	}
	return managed
}

// isBuiltinAdministratorsPrincipal mirrors
// compliance/anssi/m29_local_admin.go's isBuiltinAdministratorsPrincipal:
// a GPO Restricted Groups entry can identify BUILTIN\Administrators either
// by its well-known SID or by the bare group name, per MS-GPSB's ABNF for
// [Group Membership] lines.
func isBuiltinAdministratorsPrincipal(groupSID, groupName string) bool {
	return groupSID == builtinAdministratorsSID ||
		strings.EqualFold(groupSID, "administrators") ||
		strings.EqualFold(groupName, "administrators")
}

// normalizeOrgGUID lowercases a GPO identifier and strips the {} braces, so
// the {GUID} CN form and the bare-GUID gPLink form compare equal.
func normalizeOrgGUID(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), "{}"))
}

// dnUnderOrEqual reports whether dn is the container ouDN itself or a
// descendant of it, matched on full RDN-component boundaries - a plain
// substring test would also match an unrelated object whose DN merely
// contains ouDN's characters mid-component.
func dnUnderOrEqual(dn, ouDN string) bool {
	dn = strings.ToLower(strings.TrimSpace(dn))
	ouDN = strings.ToLower(strings.TrimSpace(ouDN))
	if ouDN == "" {
		return false
	}
	return dn == ouDN || strings.HasSuffix(dn, ","+ouDN)
}

func init() {
	audit.MustRegister(NewServerNoAdminGroupDetector())
}
