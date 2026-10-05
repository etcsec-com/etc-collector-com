package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EphemeralAdminsDetector detects PAM shadow principal configurations
type EphemeralAdminsDetector struct {
	audit.BaseDetector
}

// NewEphemeralAdminsDetector creates a new detector
func NewEphemeralAdminsDetector() *EphemeralAdminsDetector {
	return &EphemeralAdminsDetector{
		BaseDetector: audit.NewBaseDetector("EPHEMERAL_ADMINS_PAM", audit.CategoryAdvanced),
	}
}

// Detect executes the detection.
//
// Method (heuristic, not a direct container read): this scans the memberOf
// DNs of users, computers, and groups for the substring "shadow principal".
// It does NOT query CN=Shadow Principal Configuration itself, nor read
// msDS-ShadowPrincipal objects or their msDS-ShadowPrincipalSid attribute.
//
// Per Microsoft's official PAM documentation and schema reference:
//   - [MS-ADSC] "Class msDS-ShadowPrincipal"
//     (learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/5e4a3007-10de-479e-b0a4-3a96271e2640):
//     a shadow principal represents a security principal from an external
//     forest and can stand in for a user, group, or computer.
//   - [MS-ADA2] "Attribute msDS-ShadowPrincipalSid"
//     (learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/07772a36-6e4c-483d-bf52-535ae1f4974b):
//     the SID of the shadowed principal.
//   - Microsoft Learn, "Raise the bastion forest functional level..."
//     (learn.microsoft.com/en-us/microsoft-identity-manager/pam/raise-bastion-functional-level):
//     the default container is
//     CN=Shadow Principal Configuration,CN=Services,CN=Configuration.
//
// Because shadow principals can represent any security principal type, the
// scan below covers Users, Computers, and Groups (not Users only, as an
// earlier version of this detector did) via their memberOf attribute. This
// remains a substring-match approximation on group membership, not a direct
// LDAP read of the shadow principal container - it can miss non-standard
// naming and cannot enumerate shadow principals that aren't referenced by
// any memberOf value collected here.
func (d *EphemeralAdminsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedUsers []types.User
	for _, user := range data.Users {
		for _, dn := range user.MemberOf {
			if containsShadowPrincipal(dn) {
				affectedUsers = append(affectedUsers, user)
				break
			}
		}
	}

	var affectedComputers []types.Computer
	for _, computer := range data.Computers {
		for _, dn := range computer.MemberOf {
			if containsShadowPrincipal(dn) {
				affectedComputers = append(affectedComputers, computer)
				break
			}
		}
	}

	var affectedGroups []types.Group
	for _, group := range data.Groups {
		for _, dn := range group.MemberOf {
			if containsShadowPrincipal(dn) {
				affectedGroups = append(affectedGroups, group)
				break
			}
		}
	}

	count := len(affectedUsers) + len(affectedComputers) + len(affectedGroups)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Ephemeral Admin Accounts Detected (PAM Shadow Principals)",
		Description: "A user, computer, or group memberOf value contains \"shadow principal\", suggesting Privileged Access Management (PAM) time-bound/shadow-principal group membership is in use. This is a substring-match heuristic on group membership, not a direct read of the CN=Shadow Principal Configuration container or its msDS-ShadowPrincipal objects. Review to confirm the PAM configuration is intentional and properly managed.",
		Count:       count,
	}

	if data.IncludeDetails && count > 0 {
		entities := make([]types.AffectedEntity, 0, count)
		entities = append(entities, helpers.ToAffectedUserEntities(affectedUsers)...)
		entities = append(entities, helpers.ToAffectedComputerEntities(affectedComputers)...)
		entities = append(entities, helpers.ToAffectedGroupEntities(affectedGroups)...)
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

// containsShadowPrincipal checks if a DN references a shadow principal configuration
func containsShadowPrincipal(dn string) bool {
	lower := strings.ToLower(dn)
	return strings.Contains(lower, "shadow principal")
}

func init() {
	audit.MustRegister(NewEphemeralAdminsDetector())
}
