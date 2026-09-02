package adcs

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC5Detector detects ESC5: PKI Object ACL Vulnerabilities
type ESC5Detector struct {
	audit.BaseDetector
}

// NewESC5Detector creates a new detector
func NewESC5Detector() *ESC5Detector {
	return &ESC5Detector{
		BaseDetector: audit.NewBaseDetector("ESC5_PKI_OBJECT_ACL", audit.CategoryADCS),
	}
}

// isESC5AdminSID checks if a SID is a well-known admin SID
func isESC5AdminSID(sid, domainSID string) bool {
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

// isESC5DangerousAccessMask checks for dangerous permissions on PKI objects
func isESC5DangerousAccessMask(mask int) bool {
	const (
		GenericAll = 0x10000000
		WriteDACL  = 0x00040000
		WriteOwner = 0x00080000
	)
	return (mask&GenericAll) != 0 ||
		(mask&WriteDACL) != 0 ||
		(mask&WriteOwner) != 0
}

// isPKIObject checks if the DN is a PKI-related object
func isPKIObject(dn string) bool {
	dnLower := strings.ToLower(dn)
	return strings.Contains(dnLower, "cn=public key services") ||
		strings.Contains(dnLower, "cn=enrollment services")
}

// Detect executes the detection
func (d *ESC5Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		finding := types.Finding{
			Type:        d.ID(),
			Severity:    types.SeverityMedium,
			Category:    string(d.Category()),
			Title:       "ESC5 - PKI Object ACL Review Required",
			Description: "PKI-related AD objects should be reviewed for overly permissive ACLs that could allow non-admins to modify CA configuration or templates.",
			Count:       0,
			Details: map[string]interface{}{
				"note": "Domain information not available for analysis.",
			},
		}
		return []types.Finding{finding}
	}

	domainSID := data.DomainInfo.DomainSID
	affectedObjects := make(map[string]bool)
	detailsMap := make(map[string][]map[string]interface{})

	// Check ACL entries for PKI objects
	for _, acl := range data.ACLEntries {
		// Check if this is a PKI-related object
		if !isPKIObject(acl.ObjectDN) {
			continue
		}

		// Skip if trustee is an admin SID
		trusteeSID := acl.Trustee
		if isESC5AdminSID(trusteeSID, domainSID) {
			continue
		}

		// Skip deny ACEs
		if strings.ToLower(acl.AceType) == "deny" {
			continue
		}

		// Check for dangerous permissions
		if isESC5DangerousAccessMask(acl.AccessMask) {
			affectedObjects[acl.ObjectDN] = true

			if data.IncludeDetails {
				detailsMap[acl.ObjectDN] = append(detailsMap[acl.ObjectDN], map[string]interface{}{
					"trustee":    acl.Trustee,
					"accessMask": acl.AccessMask,
					"aceType":    acl.AceType,
				})
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ESC5 - PKI Object Vulnerable ACL",
		Description: "PKI-related AD objects have dangerous permissions granted to non-administrator principals. This could allow modification of CA configuration or certificate templates.",
		Count:       len(affectedObjects),
	}

	if data.IncludeDetails && len(detailsMap) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation":  "Remove GenericAll, WriteDACL, and WriteOwner permissions for non-admin principals on Public Key Services and Enrollment Services objects.",
			"affectedObjects": detailsMap,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC5Detector())
}
