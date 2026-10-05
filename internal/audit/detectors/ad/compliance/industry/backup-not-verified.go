package industry

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// BackupNotVerifiedDetector checks for backup verification compliance
type BackupNotVerifiedDetector struct {
	audit.BaseDetector
}

// NewBackupNotVerifiedDetector creates a new detector
func NewBackupNotVerifiedDetector() *BackupNotVerifiedDetector {
	return &BackupNotVerifiedDetector{
		BaseDetector: audit.NewBaseDetector("BACKUP_AD_NOT_VERIFIED", audit.CategoryCompliance),
	}
}

// Detect executes the detection.
//
// Retired detector. Backup verification status (job ran, restore
// tested) is an operational fact external to the directory - no LDAP
// attribute or Graph object carries it, and the provider has no other
// channel to reach it. The detector used to fabricate a Count:0 "reminder"
// finding regardless of any real state; a detector that can't measure
// anything must stay silent rather than emit a finding that looks like a
// measurement. Never registered (see init below) - kept only so a caller
// holding a reference still gets an honest empty result instead of a
// fabricated one.
func (d *BackupNotVerifiedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	return nil
}

// No init()/MustRegister here (retired detector) - deliberately not
// wired into audit.DefaultRegistry. See Detect above.
