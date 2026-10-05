package workspace

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DriveSharingExternalDetector detects externally shared Google Drive files
type DriveSharingExternalDetector struct {
	audit.BaseDetector
}

// NewDriveSharingExternalDetector creates a new detector
func NewDriveSharingExternalDetector() *DriveSharingExternalDetector {
	return &DriveSharingExternalDetector{
		BaseDetector: audit.NewBaseDetector("DRIVE_SHARING_EXTERNAL", audit.CategoryDriveSharing),
	}
}

// Detect checks for externally shared Drive files
func (d *DriveSharingExternalDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// TODO: Implement when Google provider is connected
	// Will query Drive API / Reports API for sharing settings
	// Files shared with "anyone with the link" or external domains = finding

	return []types.Finding{{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "External Drive Sharing",
		Description: "Google Drive files shared externally or with public links. Unrestricted sharing may expose sensitive corporate data.",
		Count:       0,
	}}
}

func init() {
	audit.MustRegister(NewDriveSharingExternalDetector())
}
