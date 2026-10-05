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

// isESC5AdminSID reports whether sid is a well-known privileged principal
// expected to hold broad rights on PKI objects by default. Reuses the same
// canonical suffix list audit.IsPrivilegedSID applies to every other ACL
// detector (Domain/Enterprise/Schema Admins, Administrators, Account/Server/
// Print/Backup Operators, Key Admins) rather than the narrower hand-picked
// list this file previously carried, which under-excluded default
// delegations and caused default installation ACLs to be reported as
// vulnerable. SYSTEM (S-1-5-18) is checked separately since it is a single
// well-known SID with no RID suffix a generic suffix match could key on.
func isESC5AdminSID(sid, _ string) bool {
	return sid == "S-1-5-18" || audit.IsPrivilegedSID(sid)
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

// isPKIObject checks if the DN is under the PKI containers in the
// configuration partition (CN=Public Key Services,CN=Services,CN=Configuration
// - this also matches its "CN=Enrollment Services" child, kept as an explicit
// check for clarity). Per SpecterOps, Certify wiki, ESC5 ("Vulnerable PKI
// Object Access Control"), this covers "any descendant object in the PKI
// container": Certificate Templates, Certification Authorities, Enrollment
// Services and NTAuthCertificates.
func isPKIObject(dn string) bool {
	dnLower := strings.ToLower(dn)
	return strings.Contains(dnLower, "cn=public key services") ||
		strings.Contains(dnLower, "cn=enrollment services")
}

// caComputerObjectDNs returns the set of computer-object DNs that host an
// Enterprise CA, matched by DNSHostName between data.CertAuthorities and
// data.Computers. SpecterOps's ESC5 definition explicitly includes "the CA
// server's computer domain object" alongside the PKI containers - a
// compromised CA computer object (e.g. via shadow credentials or RBCD) is as
// much a takeover path as a compromised PKI container, so it belongs in
// scope. Both collections already exist in DetectorData (CertAuthorities from
// CN=Enrollment Services, Computers from the standard LDAP sweep) and their
// ACEs are already gathered into data.ACLEntries by the engine, so no new
// collection is required - only wiring the lookup here.
func caComputerObjectDNs(data *audit.DetectorData) map[string]bool {
	if len(data.CertAuthorities) == 0 || len(data.Computers) == 0 {
		return nil
	}
	byDNSHostName := make(map[string]string, len(data.Computers))
	for _, c := range data.Computers {
		if c.DNSHostName != "" {
			byDNSHostName[strings.ToLower(c.DNSHostName)] = c.DN
		}
	}
	dns := make(map[string]bool)
	for _, ca := range data.CertAuthorities {
		if ca.DNSHostName == "" {
			continue
		}
		if dn, ok := byDNSHostName[strings.ToLower(ca.DNSHostName)]; ok {
			dns[dn] = true
		}
	}
	return dns
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
	caComputerDNs := caComputerObjectDNs(data)
	affectedObjects := make(map[string]bool)
	detailsMap := make(map[string][]map[string]interface{})

	// Check ACL entries for PKI objects
	for _, acl := range data.ACLEntries {
		// Check if this is a PKI-related object: a container under CN=Public
		// Key Services, or the CA server's own computer object.
		if !isPKIObject(acl.ObjectDN) && !caComputerDNs[acl.ObjectDN] {
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

	// Scope per SpecterOps, Certify wiki, ESC5 ("Vulnerable PKI Object Access
	// Control"): PKI container descendants (Certificate Templates,
	// Certification Authorities, Enrollment Services, NTAuthCertificates)
	// *and* the CA server's own computer object. When no CA's DNSHostName
	// matches a collected computer object, caComputerObjectDNs is empty and
	// coverage silently falls back to containers only - still an accurate,
	// narrower-than-ideal result, not a false claim.
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "ESC5 - PKI Object Vulnerable ACL",
		Description: "PKI-related AD objects (the Public Key Services/Enrollment Services containers and their descendants, plus the CA server's own computer object when it could be matched) have dangerous permissions granted to non-administrator principals. This could allow modification of CA configuration, certificate templates, or takeover of the CA host itself.",
		Count:       len(affectedObjects),
	}

	if data.IncludeDetails && len(detailsMap) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation":  "Remove GenericAll, WriteDACL, and WriteOwner permissions for non-admin principals on Public Key Services and Enrollment Services objects, and on the CA server's computer object.",
			"affectedObjects": detailsMap,
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC5Detector())
}
