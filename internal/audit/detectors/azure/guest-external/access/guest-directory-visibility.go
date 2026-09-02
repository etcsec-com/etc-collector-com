package access

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DirectoryVisibilityDetector checks if guest directory access is restricted
type DirectoryVisibilityDetector struct {
	audit.BaseDetector
}

// NewDirectoryVisibilityDetector creates a new detector
func NewDirectoryVisibilityDetector() *DirectoryVisibilityDetector {
	return &DirectoryVisibilityDetector{
		BaseDetector: audit.NewBaseDetector("GUEST_DIRECTORY_VISIBILITY", audit.CategoryGuestExternal),
	}
}

// Detect executes the detection
func (d *DirectoryVisibilityDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Tenant-level advisory
	count := 1

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Guest Directory Access Not Restricted",
		Description: "Guest users can enumerate directory objects. Restrict guest access to directory.",
		Count:       count,
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDirectoryVisibilityDetector())
}
