package ldap

import "regexp"

// guidToken matches one {GUID} occurrence inside a GPO extension-names
// attribute value.
var guidToken = regexp.MustCompile(`\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}`)

// parseCSEExtensionNames extracts every {GUID} token from a GPO's
// gPCMachineExtensionNames / gPCUserExtensionNames attribute values
// (GPO_LAPS_NOT_DEPLOYED). The real AD format is a sequence of
// bracket groups, each holding one or more concatenated {GUID} tokens with
// no separator inside a group - "[{CSE-GUID}{Snapin-GUID}][{CSE-GUID2}...]".
// Consumers (hasLAPSCse) only need "is this specific GUID present
// anywhere", so a flat list of every {GUID} token from both attributes,
// without preserving bracket-grouping, is sufficient and simpler than
// tracking which GUID in each group is the CSE vs. a snap-in.
func parseCSEExtensionNames(machineExtensionNames, userExtensionNames string) []string {
	var out []string
	for _, s := range []string{machineExtensionNames, userExtensionNames} {
		out = append(out, guidToken.FindAllString(s, -1)...)
	}
	return out
}
