package dangerous

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// The container "CN=Master Root Keys,CN=System" this used to
// match against does not exist on any AD (BCKUPKEY_* objects sit directly
// under CN=System with GUID-suffixed names, confirmed live on DC01:
// NO_OBJECT). The ldap provider now enumerates the real BCKUPKEY_* objects
// and fetches their ACEs directly into DomainInfo.DPAPIBackupKeyACLs; read
// that instead of filtering ACLEntries by the dead DN.

// DPAPIKeyACLDetector detects non-default access to DPAPI master keys
type DPAPIKeyACLDetector struct {
	audit.BaseDetector
}

// NewDPAPIKeyACLDetector creates a new detector
func NewDPAPIKeyACLDetector() *DPAPIKeyACLDetector {
	return &DPAPIKeyACLDetector{
		BaseDetector: audit.NewBaseDetector("DPAPI_KEY_NON_DEFAULT_ACCESS", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *DPAPIKeyACLDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
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

	// Dangerous access mask bits
	const dangerousMask = types.MaskGenericAll | types.MaskWriteDACL | types.MaskWriteOwner | types.MaskControlAccess

	if data.DomainInfo == nil {
		return nil
	}

	var affected []types.ACLEntry

	for _, ace := range data.DomainInfo.DPAPIBackupKeyACLs {
		if !strings.Contains(ace.AceType, "ALLOWED") {
			continue
		}
		if privilegedSIDs[ace.Trustee] {
			continue
		}
		if (ace.AccessMask & dangerousMask) == 0 {
			continue
		}
		affected = append(affected, ace)
	}

	if len(affected) == 0 {
		return nil
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Non-Default Access to DPAPI Master Key",
		Description: "Non-privileged principals have access to DPAPI master key objects. DPAPI keys protect credentials, certificates, and other secrets. Unauthorized access could allow decryption of protected data.",
		Count:       len(uniqueObjects),
		Details: map[string]interface{}{
			"risk":           "Decryption of DPAPI-protected credentials and secrets.",
			"recommendation": "Remove non-default access to DPAPI master key objects.",
		},
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(affected, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDPAPIKeyACLDetector())
}
