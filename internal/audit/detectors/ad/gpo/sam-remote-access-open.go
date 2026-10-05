package gpo

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// RemoteSAMDetector checks if remote SAM access is restricted
type RemoteSAMDetector struct {
	audit.BaseDetector
}

func NewRemoteSAMDetector() *RemoteSAMDetector {
	return &RemoteSAMDetector{
		BaseDetector: audit.NewBaseDetector("SAM_REMOTE_ACCESS_OPEN", audit.CategoryGPO),
	}
}

// sddlACERE matches one SDDL ACE of the shape GPO tooling actually emits for
// this policy: (AceType;AceFlags;Rights;ObjectGuid;InheritObjectGuid;SID) -
// e.g. Microsoft's own documented hardened default "(A;;RC;;;BA)". It does
// not attempt to cover object-specific ACE types (OA/OD) or conditional ACEs
// (XA/XD) - this policy's SDDL never uses them in Microsoft's own examples
// or in any published GPO tooling for it.
var sddlACERE = regexp.MustCompile(`\(([^;()]*);([^;()]*);([^;()]*);([^;()]*);([^;()]*);([^;()]*)\)`)

// samRemoteAccessSafeSIDs are the SDDL string-SID aliases that are
// legitimate holders of remote SAMR access. Matches Microsoft's own
// documented hardened default SDDL for "Network access: Restrict clients
// allowed to make remote calls to SAM": "O:SYG:SYD:(A;;RC;;;BA)" grants RC
// (READ_CONTROL) only to BA (BUILTIN\Administrators).
var samRemoteAccessSafeSIDs = map[string]bool{
	"BA": true, // BUILTIN\Administrators
	"DA": true, // Domain Admins
	"EA": true, // Enterprise Admins
	"SY": true, // LOCAL SYSTEM
}

// readControlMask is READ_CONTROL (0x00020000), the access right SAMRPC's
// access check evaluates for this policy per Microsoft's reference.
// genericAllMask is GENERIC_ALL (0x10000000), which subsumes READ_CONTROL.
const (
	readControlMask = 0x00020000
	genericAllMask  = 0x10000000
)

// aceGrantsSAMRead reports whether an SDDL ACE's Rights field (symbolic,
// e.g. "RC"/"GA", or a numeric access mask like "0x20000") includes
// READ_CONTROL or GENERIC_ALL.
func aceGrantsSAMRead(rights string) bool {
	if strings.Contains(rights, "RC") || strings.Contains(rights, "GA") {
		return true
	}
	if mask, err := strconv.ParseUint(strings.TrimSpace(rights), 0, 64); err == nil {
		return mask&(readControlMask|genericAllMask) != 0
	}
	return false
}

// sddlGrantsBroadSAMAccess parses the DACL of an SDDL security descriptor
// string and reports whether it fails to restrict remote SAM access to the
// admin-tier allowlist above - i.e. whether the configured value is
// actually equivalent to "not restricted".
//
// Source: Microsoft Learn "Network access: Restrict clients allowed to make
// remote calls to SAM" - "If the policy setting is left blank after the
// policy is defined, the policy isn't enforced", and the default hardened
// SDDL example is precisely "(A;;RC;;;BA)": Allow READ_CONTROL to
// BUILTIN\Administrators only. Any Allow ACE granting that access to a
// principal outside samRemoteAccessSafeSIDs (Everyone, Authenticated Users,
// Domain Users, an unrecognized/unresolved SID, ...) means the SDDL does not
// actually restrict remote SAM enumeration, even though the string is
// syntactically valid and contains a "D:" DACL marker.
func sddlGrantsBroadSAMAccess(sddl string) bool {
	if !strings.Contains(sddl, "D:") {
		return true // no DACL segment at all: not enforced
	}
	aces := sddlACERE.FindAllStringSubmatch(sddl, -1)
	if len(aces) == 0 {
		return true // malformed / empty DACL: not enforced
	}
	for _, ace := range aces {
		aceType, rights, sid := ace[1], ace[3], ace[6]
		if !strings.EqualFold(aceType, "A") {
			continue // not an Allow ACE (e.g. "D" = Deny grants nothing)
		}
		if !aceGrantsSAMRead(rights) {
			continue
		}
		if !samRemoteAccessSafeSIDs[strings.ToUpper(sid)] {
			return true
		}
	}
	return false
}

func (d *RemoteSAMDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "Remote SAM Access Not Restricted",
		// Source: Microsoft Learn "Network access: Restrict clients allowed
		// to make remote calls to SAM". By default this policy is "Not
		// defined". This lookup prioritizes the Default Domain Controllers
		// Policy (helpers.FindRegistrySettingString), and on a Windows
		// Server 2016+ domain controller the hard-coded fallback when
		// unconfigured is an EMPTY SDDL, which grants Everyone read access
		// "to preserve compatibility" - domain controllers are open by
		// default. This differs from non-DC member computers, which default
		// to Administrators-only remote SAM access since Windows 10 1607 /
		// Server 2016 (an OS-version-dependent default this detector does
		// not attempt to evaluate, since it reads DC-scoped GPOs).
		Description: "The Security Account Manager (SAM) remote access is not restricted via GPO, or the configured security descriptor's DACL grants remote SAMR read access to a principal broader than Administrators. By default, any authenticated user can enumerate local accounts and group memberships remotely on a domain controller, aiding reconnaissance.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingString(data.GPOPolicies, func(rs *audit.RegistrySettings) *string {
		return rs.RestrictRemoteSAM
	})

	if v == nil || sddlGrantsBroadSAMAccess(*v) {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"recommendation": "Configure RestrictRemoteSAM via GPO with the hardened SDDL O:SYG:SYD:(A;;RC;;;BA) (Microsoft's documented default for Windows 10 1607 / Server 2016+ non-domain-controllers) to limit SAM enumeration to BUILTIN\\Administrators.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewRemoteSAMDetector())
}
