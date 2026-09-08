package high

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GpoToDADetector detects GPO modification paths to Domain Admin
type GpoToDADetector struct {
	audit.BaseDetector
}

// NewGpoToDADetector creates a new detector
func NewGpoToDADetector() *GpoToDADetector {
	return &GpoToDADetector{
		BaseDetector: audit.NewBaseDetector("PATH_GPO_TO_DA", audit.CategoryAttackPaths),
	}
}

// Detect executes the detection
func (d *GpoToDADetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Find GPOs with weak ACLs (non-admin can modify). GPO.HasWeakACL
	// was never assigned by the collector; computed here instead from
	// data.GPOAcls via the dangerousMask convention (see WeakACLGPODNs).
	weakGPODNs := audit.WeakACLGPODNs(data)

	// A weak ACL alone is not a path to Domain Admin: the GPO must also be
	// LINKED (enabled link) to a container that plausibly reaches DCs or
	// privileged accounts. An orphaned GPO with a modifiable ACL and zero
	// links has no path to anything, and a GPO linked only to an OU with no
	// DC and no AdminCount-protected account underneath is not established
	// as a "path to DA" either - both were previously titled Critical
	// regardless.
	linksByGUID := make(map[string][]string, len(data.GPOLinks))
	for _, l := range data.GPOLinks {
		if !l.LinkEnabled {
			continue // a disabled link does not apply the GPO
		}
		linksByGUID[normalizeGPOGUID(l.GPOCN)] = append(linksByGUID[normalizeGPOGUID(l.GPOCN)], l.LinkedTo)
		if l.GPOGuid != "" && normalizeGPOGUID(l.GPOGuid) != normalizeGPOGUID(l.GPOCN) {
			linksByGUID[normalizeGPOGUID(l.GPOGuid)] = append(linksByGUID[normalizeGPOGUID(l.GPOGuid)], l.LinkedTo)
		}
	}

	// "Privileged" targets: any Domain Controller, or any user/computer
	// AdminSDHolder marks with AdminCount=true (current or former member of
	// a protected admin group - Domain/Enterprise/Schema Admins, etc.).
	privilegedDNs := make([]string, 0, len(data.DomainControllers))
	for _, dc := range data.DomainControllers {
		privilegedDNs = append(privilegedDNs, dc.DN)
	}
	for _, u := range data.Users {
		if u.AdminCount {
			privilegedDNs = append(privilegedDNs, u.DN)
		}
	}
	for _, c := range data.Computers {
		if c.AdminCount {
			privilegedDNs = append(privilegedDNs, c.DN)
		}
	}

	var vulnerableGpos []types.GPO
	for _, gpo := range data.GPOs {
		if !weakGPODNs[strings.ToLower(gpo.DN)] {
			continue
		}

		links := linksByGUID[normalizeGPOGUID(gpo.CN)]
		if len(links) == 0 {
			links = linksByGUID[normalizeGPOGUID(gpo.GUID)]
		}
		if len(links) == 0 {
			continue // orphaned: weak ACL, but not linked anywhere
		}
		if !anyLinkReachesPrivileged(links, data, privilegedDNs) {
			continue // linked, but only to containers with nothing privileged in them
		}

		vulnerableGpos = append(vulnerableGpos, gpo)
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "GPO Modification Path to Domain Admin",
		Description: "GPOs can be modified by non-admin users. If these GPOs apply to privileged users or DCs, attackers can achieve Domain Admin.",
		Count:       len(vulnerableGpos),
	}

	if data.IncludeDetails && len(vulnerableGpos) > 0 {
		var gpoNames []string
		entities := make([]types.AffectedEntity, len(vulnerableGpos))
		for i, gpo := range vulnerableGpos {
			name := gpo.DisplayName
			if name == "" {
				name = gpo.Name
			}
			gpoNames = append(gpoNames, name)
			entities[i] = types.AffectedEntity{
				Type:           "gpo",
				SAMAccountName: name,
			}
		}
		finding.AffectedEntities = entities
		finding.Details = map[string]interface{}{
			"vulnerableGpos": gpoNames,
			"attackVector":   "Modify GPO → Add malicious script/scheduled task → Execute on DA logon",
			"mitigation":     "Restrict GPO modification rights, implement GPO change monitoring",
		}
	}

	return []types.Finding{finding}
}

// normalizeGPOGUID lowercases a GPO identifier and strips the {} braces, so
// the {GUID} CN form and the bare-GUID gPLink form compare equal.
func normalizeGPOGUID(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), "{}"))
}

// anyLinkReachesPrivileged reports whether at least one enabled GPO link
// plausibly applies the GPO to a Domain Controller or an AdminCount-
// protected account.
//
// Known limitation: this does not model explicit GPO-inheritance blocking
// ("Block Inheritance" on a child OU) or GPO enforcement order - a
// domain-root link is treated as always reaching privileged targets, which
// is the common case but can overcount in a domain that deliberately blocks
// inheritance on its Domain Controllers / Tier-0 OUs. Modeling that would
// need the per-OU gPOptions (blockInheritance) attribute, which isn't
// currently collected.
func anyLinkReachesPrivileged(links []string, data *audit.DetectorData, privilegedDNs []string) bool {
	for _, linkedTo := range links {
		u := strings.ToUpper(strings.TrimSpace(linkedTo))
		switch {
		case strings.HasPrefix(u, "DC="):
			// Linked at the domain root: applies domain-wide by default
			// (Domain Controllers OU and privileged accounts included).
			return true
		case strings.Contains(u, "CN=SITES,"):
			for _, s := range data.Sites {
				if strings.EqualFold(s.DistinguishedName, linkedTo) && len(s.Servers) > 0 {
					return true
				}
			}
		case strings.HasPrefix(u, "OU="):
			for _, dn := range privilegedDNs {
				if dnUnderOrEqual(dn, linkedTo) {
					return true
				}
			}
		}
	}
	return false
}

// dnUnderOrEqual reports whether dn is the container ouDN itself or a
// descendant of it, matched on full RDN-component boundaries - a plain
// substring test (e.g. `strings.Contains`) would also match an unrelated
// object whose DN merely contains ouDN's characters mid-component.
func dnUnderOrEqual(dn, ouDN string) bool {
	dn = strings.ToLower(strings.TrimSpace(dn))
	ouDN = strings.ToLower(strings.TrimSpace(ouDN))
	if ouDN == "" {
		return false
	}
	return dn == ouDN || strings.HasSuffix(dn, ","+ouDN)
}

func init() {
	audit.MustRegister(NewGpoToDADetector())
}
