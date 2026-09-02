package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DcDiskSpaceDetector checks for DC disk space issues
type DcDiskSpaceDetector struct {
	audit.BaseDetector
}

// NewDcDiskSpaceDetector creates a new detector
func NewDcDiskSpaceDetector() *DcDiskSpaceDetector {
	return &DcDiskSpaceDetector{
		BaseDetector: audit.NewBaseDetector("DC_DISK_SPACE_LOW", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DcDiskSpaceDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// This would require WMI/CIM queries to check disk space
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "DC Disk Space Monitoring",
		Description: "Domain controller disk space should be monitored. Low disk space can cause AD database corruption and replication failures.",
		Count:       0, // Would be populated with actual disk space checks
		Details: map[string]interface{}{
			"dcCount":        len(data.DomainControllers),
			"recommendation": "Monitor DC disk space. NTDS.dit location should have at least 20% free space.",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDcDiskSpaceDetector())
}
