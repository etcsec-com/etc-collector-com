package gpo

import (
	"context"
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DangerousPermissionsDetector checks for GPOs with dangerous permissions
type DangerousPermissionsDetector struct {
	audit.BaseDetector
}

// NewDangerousPermissionsDetector creates a new detector
func NewDangerousPermissionsDetector() *DangerousPermissionsDetector {
	return &DangerousPermissionsDetector{
		BaseDetector: audit.NewBaseDetector("GPO_DANGEROUS_PERMISSIONS", audit.CategoryGPO),
	}
}

// Access mask constants
const (
	GenericAll    = 0x10000000
	GenericWrite  = 0x40000000
	WriteDACL     = 0x00040000
	WriteOwner    = 0x00080000
	WriteProperty = 0x00000020
)

// isAdminSID checks if a SID is a well-known admin SID
func isAdminSID(sid, domainSID string) bool {
	// Well-known SIDs to exclude
	adminSIDs := []string{
		domainSID + "-512", // Domain Admins
		domainSID + "-519", // Enterprise Admins
		domainSID + "-518", // Schema Admins
		"S-1-5-32-544",     // Administrators
		"S-1-5-18",         // SYSTEM
		"S-1-5-32-548",     // Account Operators
	}

	for _, adminSID := range adminSIDs {
		if sid == adminSID {
			return true
		}
	}
	return false
}

// isDangerousAccessMask checks if the access mask contains dangerous permissions
func isDangerousAccessMask(mask int) bool {
	return (mask&GenericAll) != 0 ||
		(mask&WriteDACL) != 0 ||
		(mask&WriteOwner) != 0 ||
		(mask&GenericWrite) != 0
}

// Detect executes the detection
func (d *DangerousPermissionsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		finding := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityHigh,
			Category:    string(d.Category()),
			Title:       "GPO Permissions Review Required",
			Description: "Group Policy Objects should be reviewed for overly permissive ACLs that allow non-administrators to modify GPO settings.",
			Count:       0,
			Details: map[string]interface{}{
				"note": "Domain information not available for analysis.",
			},
		}
		return []types.Finding{finding}
	}

	domainSID := data.DomainInfo.DomainSID
	affectedGPOs := make(map[string]bool)
	detailsMap := make(map[string][]map[string]interface{})

	gpoByDN := make(map[string]*types.GPO)
	for i := range data.GPOs {
		gpoByDN[data.GPOs[i].DN] = &data.GPOs[i]
	}

	// Check GPOAcls for dangerous permissions by non-admin principals
	for _, acl := range data.GPOAcls {
		// Skip if trustee is an admin SID
		if isAdminSID(acl.TrusteeSID, domainSID) {
			continue
		}

		// Skip deny ACEs - we're looking for granted permissions
		if strings.ToLower(acl.AceType) == "deny" {
			continue
		}

		// Check for dangerous permissions
		if isDangerousAccessMask(acl.AccessMask) {
			affectedGPOs[acl.GPODN] = true

			if data.IncludeDetails {
				detailsMap[acl.GPODN] = append(detailsMap[acl.GPODN], map[string]interface{}{
					"trustee":    acl.Trustee,
					"trusteeSID": acl.TrusteeSID,
					"accessMask": acl.AccessMask,
					"aceType":    acl.AceType,
				})
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "GPO Dangerous Permissions",
		Description: "Group Policy Objects with dangerous permissions granted to non-administrator principals. This allows unauthorized modification of GPO settings.",
		Count:       len(affectedGPOs),
	}

	if data.IncludeDetails && len(affectedGPOs) > 0 {
		// Sorted by DN (T_046/B_048): affectedGPOs is a map, so ranging it
		// directly gives a randomized order per process — same input,
		// different JSON, different sha256 across runs.
		dns := make([]string, 0, len(affectedGPOs))
		for dn := range affectedGPOs {
			dns = append(dns, dn)
		}
		sort.Strings(dns)

		entities := make([]types.AffectedEntity, 0, len(affectedGPOs))
		for _, dn := range dns {
			if g, ok := gpoByDN[dn]; ok {
				entities = append(entities, types.GPOToAffectedEntity(g))
			} else {
				entities = append(entities, types.AffectedEntity{Type: "gpo", DN: dn})
			}
		}
		finding.AffectedEntities = entities
	}

	if data.IncludeDetails && len(detailsMap) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Review and remove GenericAll, GenericWrite, WriteDACL, and WriteOwner permissions for non-admin principals on GPOs.",
			"affectedGPOs":   detailsMap,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousPermissionsDetector())
}
