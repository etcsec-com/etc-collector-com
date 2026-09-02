package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminSdHolderModifiedDetector detects modified AdminSDHolder permissions
type AdminSdHolderModifiedDetector struct {
	audit.BaseDetector
}

// NewAdminSdHolderModifiedDetector creates a new detector
func NewAdminSdHolderModifiedDetector() *AdminSdHolderModifiedDetector {
	return &AdminSdHolderModifiedDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_SD_HOLDER_MODIFIED", audit.CategoryAdvanced),
	}
}

// isDefaultAdminSDHolderSID checks if a SID should have permissions on AdminSDHolder
func isDefaultAdminSDHolderSID(sid, domainSID string) bool {
	// Default SIDs that should have permissions on AdminSDHolder
	defaultSIDs := []string{
		domainSID + "-512", // Domain Admins
		domainSID + "-519", // Enterprise Admins
		domainSID + "-518", // Schema Admins
		"S-1-5-32-544",     // Administrators
		"S-1-5-18",         // SYSTEM
		"S-1-5-32-548",     // Account Operators
	}

	for _, defaultSID := range defaultSIDs {
		if sid == defaultSID {
			return true
		}
	}
	return false
}

// isAdminSDHolderObject checks if the DN is the AdminSDHolder object
func isAdminSDHolderObject(dn string) bool {
	dnLower := strings.ToLower(dn)
	return strings.Contains(dnLower, "cn=adminsdholder")
}

// dangerousMask mirrors the sibling permission-family detectors (schema-permissions.go,
// dpapi-key-acl.go): only ACEs granting actual write-level control are a real SDProp
// propagation risk. T_129 — this detector never read AccessMask at all before this fix
// (motif(b), same signature as the T_024 bugs), so ANY allow ACE from a non-default SID —
// even a read-only grant — flagged HIGH severity indiscriminately.
const dangerousMask = types.MaskGenericAll | types.MaskWriteDACL | types.MaskWriteOwner | types.MaskWriteProperty

// Detect executes the detection
func (d *AdminSdHolderModifiedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		finding := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityHigh,
			Category:    string(d.Category()),
			Title:       "AdminSDHolder Review Required",
			Description: "AdminSDHolder permissions should be reviewed. Modifications propagate to all protected accounts (Domain Admins, Enterprise Admins, etc.) via SDProp process.",
			Count:       0,
			Details: map[string]interface{}{
				"note": "Domain information not available for analysis.",
			},
		}
		return []types.Finding{finding}
	}

	domainSID := data.DomainInfo.DomainSID
	seen := make(map[string]bool)
	var nonStandardACEs []types.ACLEntry

	// Check ACL entries for AdminSDHolder object
	for _, acl := range data.ACLEntries {
		// Check if this is the AdminSDHolder object
		if !isAdminSDHolderObject(acl.ObjectDN) {
			continue
		}

		// Skip deny ACEs for this analysis. T_129 — this used to compare
		// against the literal string "deny", which real AceType values
		// (aceTypeToString, acl_parser.go: "ACCESS_DENIED", "ACCESS_DENIED_OBJECT", …)
		// never equal — the filter was a silent no-op, letting every deny ACE
		// through as if it were a grant. audit.IsGrantACE is the established
		// substring-based check every sibling permission detector already uses.
		if !audit.IsGrantACE(acl.AceType) {
			continue
		}

		// Only ACEs granting a dangerous (write-level) right are a real
		// SDProp propagation risk — a read-only grant is noise, not a
		// modification (T_129 fix).
		if (acl.AccessMask & dangerousMask) == 0 {
			continue
		}

		// Check if this is a non-default SID with permissions
		trusteeSID := acl.Trustee
		if !isDefaultAdminSDHolderSID(trusteeSID, domainSID) {
			key := trusteeSID + ":" + acl.ObjectDN
			if seen[key] {
				continue
			}
			seen[key] = true
			nonStandardACEs = append(nonStandardACEs, acl)
		}
	}

	count := 0
	if len(nonStandardACEs) > 0 {
		count = 1 // Report as a single finding since it's one object
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "AdminSDHolder Modified",
		Description: "AdminSDHolder contains non-standard permissions. These modifications propagate to all protected accounts (Domain Admins, Enterprise Admins, etc.) via the SDProp process.",
		Count:       count,
	}

	if data.IncludeDetails && len(nonStandardACEs) > 0 {
		entities := make([]types.AffectedEntity, 0, len(nonStandardACEs))
		for _, ace := range nonStandardACEs {
			ent := audit.ACLEntryToAffectedEntity(ace, data.ObjectByDN, data.ObjectBySID)
			if ent.Type == "" {
				continue // unknown right — skip
			}
			entities = append(entities, ent)
		}
		finding.AffectedEntities = entities
		finding.Details = map[string]interface{}{
			"recommendation": "Review AdminSDHolder ACL and remove any non-standard principals. Only default admin groups should have permissions.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminSdHolderModifiedDetector())
}
