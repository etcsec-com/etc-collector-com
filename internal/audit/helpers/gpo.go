package helpers

import (
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// GPOLinkScope describes how broadly a GPO is applied across the AD topology.
// Computed from the gPLink attribute of OUs/Sites/Domain-root by walking the
// list of GPOLink entries collected during the audit.
type GPOLinkScope struct {
	// LinkedToDomain = true when the GPO is linked at the domain root
	// (DN of the link target == data.DomainInfo.DomainDN). This is the
	// signal ANSSI R74+ / R10** are looking for: "deployment domain-wide".
	LinkedToDomain bool

	// LinkedOUCount = number of distinct OUs/Sites/containers (other than
	// the domain root) where the GPO is enabled-and-not-disabled. Useful
	// for R10*: a GPO scoped to a small number of OUs (e.g. only Tier 0)
	// matches the "sensitive workstations" pattern.
	LinkedOUCount int

	// LinkedTier0OU = true when at least one of the linked OUs has a DN
	// containing a Tier 0 marker ("tier0", "tier-0", "t0", "admin"). Used
	// as the precise signal for R10* (CredGuard scoped to Tier 0).
	LinkedTier0OU bool
}

// ComputeGPOScope walks the data.GPOLinks list and returns the scope for the
// given GPO GUID. Disabled-link entries are ignored. Returns zero-value
// GPOLinkScope when no link is found (caller should treat that as "GPO has
// no effect" for ANSSI scoring purposes).
//
// v3.1.18 — replaces the v3.1.17 heuristic that counted distinct GPOs to
// approximate "domain-wide rollout". This is now exact.
func ComputeGPOScope(data *audit.DetectorData, gpoGUID, domainDN string) GPOLinkScope {
	var s GPOLinkScope
	if data == nil {
		return s
	}
	domainDN = strings.ToLower(strings.TrimSpace(domainDN))
	gpoGUID = strings.ToLower(strings.TrimSpace(gpoGUID))

	for _, link := range data.GPOLinks {
		// Match either GPOCN or GPOGuid against gpoGUID. AD stores the GPO
		// reference in gPLink as a DN containing the GUID — both fields
		// here come from the same origin so case-insensitive contains is OK.
		ref := strings.ToLower(link.GPOCN)
		if ref == "" {
			ref = strings.ToLower(link.GPOGuid)
		}
		if !strings.Contains(ref, gpoGUID) {
			continue
		}
		if link.Disabled || !link.LinkEnabled {
			continue
		}
		target := strings.ToLower(link.LinkedTo)
		if target == "" {
			continue
		}
		// Domain-root link?
		if target == domainDN {
			s.LinkedToDomain = true
			continue
		}
		s.LinkedOUCount++
		if isTier0OUDN(target) {
			s.LinkedTier0OU = true
		}
	}
	return s
}

// isTier0OUDN returns true when the OU/container DN contains a textual
// marker suggesting it groups Tier 0 admin assets. ANSSI doesn't prescribe
// a naming convention; this heuristic catches the common patterns.
func isTier0OUDN(dn string) bool {
	low := strings.ToLower(dn)
	for _, marker := range []string{
		"ou=tier0", "ou=tier-0", "ou=t0", "ou=tier 0", "ou=admin", "ou=admins",
		"ou=privileged", "ou=paw", "ou=tier_0",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}
