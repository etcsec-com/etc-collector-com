package adcs

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC7Detector detects ESC7: Vulnerable CA ACL
type ESC7Detector struct {
	audit.BaseDetector
}

// NewESC7Detector creates a new detector
func NewESC7Detector() *ESC7Detector {
	return &ESC7Detector{
		BaseDetector: audit.NewBaseDetector("ESC7_CA_VULNERABLE_ACL", audit.CategoryADCS),
	}
}

// CA-specific access rights
const (
	ManageCA           = 0x00000001
	ManageCertificates = 0x00000002
)

// isESC7AdminSID checks if a SID is a well-known admin SID
func isESC7AdminSID(sid, domainSID string) bool {
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

// isESC7DangerousAccessMask checks for dangerous CA permissions
func isESC7DangerousAccessMask(mask int) bool {
	return (mask&ManageCA) != 0 ||
		(mask&ManageCertificates) != 0 ||
		(mask&WriteDACL) != 0 ||
		(mask&WriteOwner) != 0
}

// isEnrollmentServicesObject checks if the DN is a CA Enrollment Services object
func isEnrollmentServicesObject(dn string) bool {
	dnLower := strings.ToLower(dn)
	return strings.Contains(dnLower, "cn=enrollment services")
}

// Detect executes the detection
func (d *ESC7Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return []types.Finding{{
			Type:        d.ID(),
			Severity:    types.SeverityHigh,
			Category:    string(d.Category()),
			Title:       "ESC7 - CA ACL Review Required",
			Description: "Certificate Authority ACLs should be reviewed for ManageCA or ManageCertificates rights granted to non-administrators.",
			Count:       0,
		}}
	}

	domainSID := data.DomainInfo.DomainSID
	affectedCAs := make(map[string]bool)
	var affectedEntities []types.AffectedEntity

	// Check ACL entries for Enrollment Services objects
	for _, acl := range data.ACLEntries {
		if !isEnrollmentServicesObject(acl.ObjectDN) {
			continue
		}
		if isESC7AdminSID(acl.Trustee, domainSID) {
			continue
		}
		if strings.ToLower(acl.AceType) == "deny" {
			continue
		}

		if isESC7DangerousAccessMask(acl.AccessMask) {
			affectedCAs[acl.ObjectDN] = true

			if data.IncludeDetails {
				rights := describeCAPermissions(acl.AccessMask)
				affectedEntities = append(affectedEntities, types.AffectedEntity{
					Type:        "ca",
					DN:          acl.ObjectDN,
					Description: fmt.Sprintf("Trustee: %s, Rights: %s", acl.Trustee, strings.Join(rights, ", ")),
				})
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ESC7 - CA Vulnerable ACL",
		Description: "Certificate Authority objects have dangerous permissions granted to non-administrator principals. ManageCA or ManageCertificates rights allow certificate issuance and CA configuration changes.",
		Count:       len(affectedCAs),
	}

	if data.IncludeDetails && len(affectedEntities) > 0 {
		finding.AffectedEntities = affectedEntities
	}

	return []types.Finding{finding}
}

// describeCAPermissions returns a human-readable description of the permissions
func describeCAPermissions(mask int) []string {
	var permissions []string
	if (mask & ManageCA) != 0 {
		permissions = append(permissions, "ManageCA")
	}
	if (mask & ManageCertificates) != 0 {
		permissions = append(permissions, "ManageCertificates")
	}
	if (mask & WriteDACL) != 0 {
		permissions = append(permissions, "WriteDACL")
	}
	if (mask & WriteOwner) != 0 {
		permissions = append(permissions, "WriteOwner")
	}
	return permissions
}

func init() {
	audit.MustRegister(NewESC7Detector())
}
