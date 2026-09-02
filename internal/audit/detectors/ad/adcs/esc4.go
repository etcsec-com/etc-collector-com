package adcs

import (
	"context"
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC4Detector detects ESC4: Vulnerable Certificate Template ACL
type ESC4Detector struct {
	audit.BaseDetector
}

// NewESC4Detector creates a new detector
func NewESC4Detector() *ESC4Detector {
	return &ESC4Detector{
		BaseDetector: audit.NewBaseDetector("ESC4_VULNERABLE_TEMPLATE_ACL", audit.CategoryADCS),
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

// isDangerousAccessMask checks if the access mask contains dangerous permissions for templates
func isDangerousAccessMask(mask int) bool {
	return (mask&GenericAll) != 0 ||
		(mask&WriteDACL) != 0 ||
		(mask&WriteOwner) != 0 ||
		(mask&WriteProperty) != 0
}

// Detect executes the detection
func (d *ESC4Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		finding := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityCritical,
			Category:    string(d.Category()),
			Title:       "ESC4 - Certificate Template ACL Review Required",
			Description: "Certificate templates with authentication capability should be reviewed for overly permissive ACLs that allow non-admins to modify template properties.",
			Count:       0,
			Details: map[string]interface{}{
				"note": "Domain information not available for analysis.",
			},
		}
		return []types.Finding{finding}
	}

	domainSID := data.DomainInfo.DomainSID

	// Build map of template DNs for quick lookup
	templateDNs := make(map[string]*types.CertTemplate)
	for i := range data.CertTemplates {
		templateDNs[data.CertTemplates[i].DN] = &data.CertTemplates[i]
	}

	affectedTemplates := make(map[string]*types.CertTemplate)
	dangerousACEsMap := make(map[string][]types.ACLEntry)
	detailsMap := make(map[string][]map[string]interface{})

	// Check ACL entries for certificate templates
	for _, acl := range data.ACLEntries {
		// Check if this ACL is for a certificate template
		template, isTemplate := templateDNs[acl.ObjectDN]
		if !isTemplate {
			continue
		}

		// Skip if trustee is an admin SID
		trusteeSID := acl.Trustee
		if isAdminSID(trusteeSID, domainSID) {
			continue
		}

		// Skip deny ACEs
		if strings.ToLower(acl.AceType) == "deny" {
			continue
		}

		// Check for dangerous permissions
		if isDangerousAccessMask(acl.AccessMask) {
			affectedTemplates[template.DN] = template
			dangerousACEsMap[template.DN] = append(dangerousACEsMap[template.DN], acl)

			if data.IncludeDetails {
				templateName := template.Name
				if templateName == "" {
					templateName = template.DisplayName
				}

				detailsMap[templateName] = append(detailsMap[templateName], map[string]interface{}{
					"dn":         template.DN,
					"trustee":    acl.Trustee,
					"accessMask": acl.AccessMask,
					"aceType":    acl.AceType,
				})
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "ESC4 - Vulnerable Certificate Template ACL",
		Description: "Certificate templates with dangerous permissions granted to non-administrator principals. This allows unauthorized modification of template properties, potentially enabling certificate-based attacks.",
		Count:       len(affectedTemplates),
	}

	if data.IncludeDetails && len(affectedTemplates) > 0 {
		// Sorted by DN (T_046/B_048): affectedTemplates is a map, so ranging
		// it directly gives a randomized order per process — same input,
		// different JSON, different sha256 across runs.
		dns := make([]string, 0, len(affectedTemplates))
		for dn := range affectedTemplates {
			dns = append(dns, dn)
		}
		sort.Strings(dns)

		entities := make([]types.AffectedEntity, 0, len(affectedTemplates))
		for _, dn := range dns {
			t := affectedTemplates[dn]
			ownerSID := ""
			if data.ObjectOwners != nil {
				ownerSID = data.ObjectOwners[t.DN]
			}
			entities = append(entities, helpers.CertTemplateToAffectedEntityWithACL(t, ownerSID, dangerousACEsMap[t.DN]))
		}
		finding.AffectedEntities = entities
	}

	if data.IncludeDetails && len(detailsMap) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation":    "Remove GenericAll, GenericWrite, WriteDACL, WriteOwner, and WriteProperty permissions for non-admin principals on certificate templates.",
			"affectedTemplates": detailsMap,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC4Detector())
}
