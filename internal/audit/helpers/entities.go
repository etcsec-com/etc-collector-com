// Package helpers provides utility functions for audit detectors
package helpers

import (
	"strings"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ToAffectedUserEntities converts users to affected entities (TypeScript-compatible format)
func ToAffectedUserEntities(users []types.User) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(users))
	for i := range users {
		entities[i] = types.UserToAffectedEntity(&users[i])
	}
	return entities
}

// ToAffectedComputerEntities converts computers to affected entities (TypeScript-compatible format)
func ToAffectedComputerEntities(computers []types.Computer) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(computers))
	for i := range computers {
		entities[i] = types.ComputerToAffectedEntity(&computers[i])
	}
	return entities
}

// ToAffectedGroupEntities converts groups to affected entities (TypeScript-compatible format)
func ToAffectedGroupEntities(groups []types.Group) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(groups))
	for i := range groups {
		entities[i] = types.GroupToAffectedEntity(&groups[i])
	}
	return entities
}

// ToAffectedGPOEntities converts GPOs to affected entities
func ToAffectedGPOEntities(gpos []types.GPO) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(gpos))
	for i := range gpos {
		entities[i] = types.GPOToAffectedEntity(&gpos[i])
	}
	return entities
}

// ToAffectedTrustEntities converts Trusts to affected entities
func ToAffectedTrustEntities(trusts []types.Trust) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(trusts))
	for i := range trusts {
		entities[i] = types.TrustToAffectedEntity(&trusts[i])
	}
	return entities
}

// RoleAssignmentsToAffectedEntities converts Azure role assignments to affected entities
func RoleAssignmentsToAffectedEntities(roleAssignments []types.RoleAssignment) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(roleAssignments))
	for i := range roleAssignments {
		entities[i] = types.RoleAssignmentToAffectedEntity(&roleAssignments[i])
	}
	return entities
}

// FormatTime formats time for display
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// ContainsGroupCI checks if any memberOf DN contains the group name (case-insensitive)
func ContainsGroupCI(memberOf []string, groupName string) bool {
	lowerGroup := strings.ToLower(groupName)
	for _, dn := range memberOf {
		if strings.Contains(strings.ToLower(dn), "cn="+lowerGroup) {
			return true
		}
	}
	return false
}

// IsInAnyGroup checks if user is in any of the specified groups
func IsInAnyGroup(memberOf []string, groups []string) bool {
	for _, g := range groups {
		if ContainsGroupCI(memberOf, g) {
			return true
		}
	}
	return false
}

// AdminGroups is the list of standard admin groups
var AdminGroups = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Account Operators",
	"Server Operators",
	"Backup Operators",
	"Print Operators",
}

// ToAffectedCertTemplateEntities converts cert templates to affected entities with full ADCS attributes
func ToAffectedCertTemplateEntities(templates []types.CertTemplate) []types.AffectedEntity {
	entities := make([]types.AffectedEntity, len(templates))
	for i := range templates {
		entities[i] = types.CertTemplateToAffectedEntity(&templates[i])
	}
	return entities
}

// CertTemplateToAffectedEntityWithACL converts a cert template with ACL data (owner + dangerous permissions)
func CertTemplateToAffectedEntityWithACL(t *types.CertTemplate, ownerSID string, aces []types.ACLEntry) types.AffectedEntity {
	entity := types.CertTemplateToAffectedEntity(t)
	if entity.CertTemplate != nil {
		entity.CertTemplate.Owner = ownerSID
		if len(aces) > 0 {
			perms := make([]types.CertTemplatePermission, len(aces))
			for i, ace := range aces {
				perms[i] = types.CertTemplatePermission{
					Trustee:    ace.Trustee,
					AccessMask: ace.AccessMask,
					AceType:    ace.AceType,
					Right:      describeAccessMask(ace.AccessMask),
				}
			}
			entity.CertTemplate.Permissions = perms
		}
	}
	return entity
}

func describeAccessMask(mask int) string {
	var rights []string
	if mask&0x10000000 != 0 {
		rights = append(rights, "GenericAll")
	}
	if mask&0x40000000 != 0 {
		rights = append(rights, "GenericWrite")
	}
	if mask&0x00040000 != 0 {
		rights = append(rights, "WriteDACL")
	}
	if mask&0x00080000 != 0 {
		rights = append(rights, "WriteOwner")
	}
	if mask&0x00000020 != 0 {
		rights = append(rights, "WriteProperty")
	}
	return strings.Join(rights, ",")
}

// GetUniqueObjects returns unique object DNs from ACL entries
func GetUniqueObjects(entries []types.ACLEntry) []string {
	seen := make(map[string]bool)
	var result []string

	for _, ace := range entries {
		if !seen[ace.ObjectDN] {
			seen[ace.ObjectDN] = true
			result = append(result, ace.ObjectDN)
		}
	}

	return result
}
