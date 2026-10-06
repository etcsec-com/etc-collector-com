package dangerous

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ServerTrustAccountDetector detects rights to set Server Trust Account flag
type ServerTrustAccountDetector struct {
	audit.BaseDetector
}

// NewServerTrustAccountDetector creates a new detector
func NewServerTrustAccountDetector() *ServerTrustAccountDetector {
	return &ServerTrustAccountDetector{
		BaseDetector: audit.NewBaseDetector("SERVER_TRUST_ACCOUNT_RIGHT", audit.CategoryPermissions),
	}
}

// Detect executes the detection.
//
// A write grant on userAccountControl can be scoped two ways in a real ACL,
// and both must be checked (Microsoft Learn, Win32 AD Schema reference):
//   - the User-Account-Control attribute's own schemaIDGUID
//     (bf967a68-0de6-11d0-a285-00aa003049e2, "User-Account-Control
//     attribute"), or
//   - the User-Account-Restrictions property set's Rights-GUID
//     (4c164200-20c0-11d0-a768-00aa006e0529, "User-Account-Restrictions
//     property set"), whose documented members include
//     User-Account-Control. This is how the AD Users and Computers
//     delegation wizard actually grants "write account restrictions" -
//     ACEs written this way were previously invisible to this detector.
func (d *ServerTrustAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// userAccountControl attribute GUID, and the property set that includes it
	const uacGUID = "bf967a68-0de6-11d0-a285-00aa003049e2"
	const uacPropertySetGUID = "4c164200-20c0-11d0-a768-00aa006e0529"

	// Build privileged SIDs set
	privilegedSIDs := make(map[string]bool)
	privilegedSIDs["S-1-5-18"] = true // SYSTEM
	privilegedSIDs["S-1-3-0"] = true  // Creator Owner
	privilegedSIDs["S-1-5-10"] = true // SELF
	if data.DomainInfo != nil && data.DomainInfo.DomainSID != "" {
		for suffix := range types.PrivilegedSIDSuffixes {
			privilegedSIDs[data.DomainInfo.DomainSID+suffix] = true
		}
	}

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if !strings.Contains(ace.AceType, "ALLOWED") {
			continue
		}
		if (ace.AccessMask & types.MaskWriteProperty) == 0 {
			continue
		}
		ot := strings.ToLower(ace.ObjectType)
		if ot != uacGUID && ot != uacPropertySetGUID {
			continue
		}
		if privilegedSIDs[ace.Trustee] {
			continue
		}
		affected = append(affected, ace)
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Users with Rights to Set Server Trust Account",
		Description: "Non-privileged principals can modify the userAccountControl attribute to set the SERVER_TRUST_ACCOUNT flag. This could allow creating rogue domain controllers for DCShadow attacks.",
		Count:       len(uniqueObjects),
		Details: map[string]interface{}{
			"risk":           "Rogue domain controller creation via DCShadow attack.",
			"recommendation": "Remove write access to userAccountControl from non-privileged accounts.",
		},
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
	audit.MustRegister(NewServerTrustAccountDetector())
}
