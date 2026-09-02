package dangerous

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SchemaPermissionsDetector detects non-standard permissions on the AD schema
type SchemaPermissionsDetector struct {
	audit.BaseDetector
}

// NewSchemaPermissionsDetector creates a new detector
func NewSchemaPermissionsDetector() *SchemaPermissionsDetector {
	return &SchemaPermissionsDetector{
		BaseDetector: audit.NewBaseDetector("SCHEMA_NON_STANDARD_PERMISSIONS", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *SchemaPermissionsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
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
	const dangerousMask = types.MaskGenericAll | types.MaskWriteDACL | types.MaskWriteOwner | types.MaskWriteProperty

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if !strings.Contains(strings.ToLower(ace.ObjectDN), "cn=schema,cn=configuration,") {
			continue
		}
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

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Non-Standard Schema Permissions",
		Description: "Non-privileged principals have write or modify permissions on the Active Directory schema. Schema modifications are irreversible and affect the entire forest, representing a critical risk.",
		Count:       len(uniqueObjects),
		Details: map[string]interface{}{
			"risk":           "Irreversible schema modifications affecting the entire forest.",
			"recommendation": "Remove non-standard write permissions from the AD schema container.",
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
	audit.MustRegister(NewSchemaPermissionsDetector())
}
