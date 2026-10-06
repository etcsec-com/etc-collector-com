package moderate

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WritePropertyExtendedDetector detects extended write property rights
type WritePropertyExtendedDetector struct {
	audit.BaseDetector
}

// NewWritePropertyExtendedDetector creates a new detector
func NewWritePropertyExtendedDetector() *WritePropertyExtendedDetector {
	return &WritePropertyExtendedDetector{
		BaseDetector: audit.NewBaseDetector("ACL_WRITE_PROPERTY_EXTENDED", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *WritePropertyExtendedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// The User-Logon property set and its three individually-delegable logon
	// attributes. GUIDs read from a forest's Extended-Rights (rightsGuid) and
	// Schema (schemaIDGUID), never from memory - a lookalike attribute GUID
	// silently monitors the wrong thing.
	//
	// Deliberately absent, and why:
	//   - 00299570 (User-Force-Change-Password) is a control-access right,
	//     never granted via WRITE_PROPERTY: already owned by
	//     ACL_USER_FORCE_CHANGE_PASSWORD and ANSSI_R12_1_FORCE_PWD_RESET_PRIVS.
	//   - bf967a68 (userAccountControl - mislabeled "Script-Path" before this
	//     fix) is already covered, non-admin WRITE_PROPERTY included, by
	//     SERVER_TRUST_ACCOUNT_RIGHT (critical).
	//   - bf967950 (description - mislabeled "Home-Directory" before this
	//     fix) grants no elevation by itself; its VALUE is read by
	//     PASSWORD_IN_DESCRIPTION and DOMAIN_ADMIN_IN_DESCRIPTION, not who
	//     can write it.
	//   - 5b47d60f (msDS-KeyCredentialLink) is out of scope for this ticket:
	//     a dedicated detector is under founder review.
	loginProperties := map[string]bool{
		"5f202010-79a5-11d0-9020-00c04fc2d4cf": true, // User-Logon (property set)
		"bf9679a8-0de6-11d0-a285-00aa003049e2": true, // Script-Path
		"bf967a05-0de6-11d0-a285-00aa003049e2": true, // Profile-Path
		"bf967985-0de6-11d0-a285-00aa003049e2": true, // Home-Directory
	}

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if !loginProperties[strings.ToLower(ace.ObjectType)] {
			continue
		}
		if !audit.IsGrantACE(ace.AceType) {
			continue
		}
		if ace.InheritOnly {
			continue
		}
		if (ace.AccessMask & types.MaskWriteProperty) == 0 {
			continue
		}
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue
		}
		// Computer objects inherit these attributes from the user schema
		// class but never use them for logon; the class's own
		// defaultSecurityDescriptor grants CREATOR OWNER (the joiner)
		// WRITE_PROPERTY on the User-Logon set on every computer by
		// construction, so without this filter every domain-joined computer
		// is a false positive.
		meta := data.ObjectByDN[ace.ObjectDN]
		if meta == nil || meta.EntityType != types.EntityTypeUser {
			continue
		}
		affected = append(affected, ace)
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Write Access to Logon Script, Profile or Home-Directory Attributes",
		Description: "Non-administrative principals hold WRITE_PROPERTY on the logon attributes of user accounts (the User-Logon property set, scriptPath, profilePath, or homeDirectory). Writing scriptPath or profilePath lets the holder point the account's next logon at content they control. Built-in administrative groups, SYSTEM, SELF and CREATOR OWNER are excluded, inherit-only ACEs are ignored, and computer accounts are excluded since these attributes control interactive logon, not machine authentication. Reset-password and userAccountControl delegations are reported by ACL_USER_FORCE_CHANGE_PASSWORD and SERVER_TRUST_ACCOUNT_RIGHT.",
		Count:       len(uniqueObjects),
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(affected, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWritePropertyExtendedDetector())
}
