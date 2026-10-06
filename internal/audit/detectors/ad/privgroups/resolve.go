// Package privgroups resolves AD group privilege by SID RID suffix instead
// of by group CN, the same non-localized match
// accounts/privileged/sensitive-delegation.go's privilegedGroupDNsBySID
// already applies for SENSITIVE_DELEGATION. That detector is confirmed and
// out of scope to touch here, so this package is a new, shared home for the
// same mechanism generalized to an arbitrary RID suffix set - each caller
// needs its OWN group set, not the fixed eleven of
// types.PrivilegedSIDSuffixes.
package privgroups

import (
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DNsBySIDSuffix returns the lowercased DN of every collected group whose
// SID ends in one of the given RID suffixes (e.g. "-512", "-551",
// "S-1-5-32-544" also works since the match is a plain string suffix).
//
// The lookup runs entirely through DetectorData.ObjectBySID: engine.collectData
// builds it in two steps (engine.go) - buildObjectIndex indexes every
// types.Group by g.ObjectSID (detector.go's DetectorData.ObjectByDN cache),
// then buildSIDIndex reverses that DN-keyed cache into the SID-keyed view
// documented at DetectorData.ObjectBySID (detector.go). g.ObjectSID itself
// comes straight off the wire: providers/ldap/parser.go's parseGroup decodes
// the group's raw "objectSid" LDAP attribute.
//
// A privileged group whose SID never makes it into that index - not
// collected into data.Groups, or collected with an empty ObjectSID - is
// silently excluded here: none of its members can be identified as
// privileged by this function. That is a property of the shared index, not
// of this file, and it fails closed (under-detection), never open.
func DNsBySIDSuffix(data *audit.DetectorData, suffixes []string) map[string]bool {
	dns := make(map[string]bool, len(suffixes))
	for sid, meta := range data.ObjectBySID {
		if meta == nil || meta.EntityType != types.EntityTypeGroup {
			continue
		}
		for _, suffix := range suffixes {
			if strings.HasSuffix(sid, suffix) {
				dns[strings.ToLower(meta.DN)] = true
				break
			}
		}
	}
	return dns
}

// IsMemberOfAny reports whether any DN in memberOf resolves to a group DN
// in dns (as produced by DNsBySIDSuffix). Matching is on direct memberOf
// entries only, never on nested/transitive group membership - the same
// scope limit privilegedGroupDNsBySID / isMemberOfPrivilegedGroup document
// in sensitive-delegation.go.
func IsMemberOfAny(memberOf []string, dns map[string]bool) bool {
	for _, dn := range memberOf {
		if dns[strings.ToLower(dn)] {
			return true
		}
	}
	return false
}
