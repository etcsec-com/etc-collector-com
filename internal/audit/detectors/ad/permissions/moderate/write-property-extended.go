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
	// User-Force-Change-Password is a control-access right, not an attribute:
	// it is granted via CONTROL_ACCESS, never via WRITE_PROPERTY.
	controlAccessProperties := map[string]bool{
		"00299570-246d-11d0-a768-00aa006e0529": true, // User-Force-Change-Password
	}
	// These are ordinary attributes, granted via WRITE_PROPERTY.
	writeProperties := map[string]bool{
		"bf967a68-0de6-11d0-a285-00aa003049e2": true, // Script-Path
		"bf967950-0de6-11d0-a285-00aa003049e2": true, // Home-Directory
		"5f202010-79a5-11d0-9020-00c04fc2d4cf": true, // ms-DS-Key-Credential-Link (Shadow Credentials)
	}

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		objectType := strings.ToLower(ace.ObjectType)

		var isDangerous bool
		switch {
		case controlAccessProperties[objectType]:
			isDangerous = (ace.AccessMask & types.MaskControlAccess) != 0
		case writeProperties[objectType]:
			isDangerous = (ace.AccessMask & types.MaskWriteProperty) != 0
		}

		if isDangerous {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Extended Write Property Rights",
		Description: "Principals with dangerous extended write property rights. Can modify script paths, home directories, or key credentials.",
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
