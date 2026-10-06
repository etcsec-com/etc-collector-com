package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SysvolNetlogonDetector checks for SYSVOL/NETLOGON permission issues
type SysvolNetlogonDetector struct {
	audit.BaseDetector
}

// NewSysvolNetlogonDetector creates a new detector
func NewSysvolNetlogonDetector() *SysvolNetlogonDetector {
	return &SysvolNetlogonDetector{
		BaseDetector: audit.NewBaseDetector("SYSVOL_NETLOGON_PERMISSIONS", audit.CategoryNetwork),
	}
}

// Detect executes the detection.
//
// SYSVOL/NETLOGON share-level permissions (the DACL on the SMB
// share and the underlying NTFS ACL) are not collectable today: the SMB
// client in internal/providers/smb only reads file content/attributes
// (ReadFile, ListDir, Stat) via go-smb2, whose public API exposes no
// security descriptor / QUERY_INFO(SECURITY) call, and DetectorData
// carries no such field. This detector used to fire an unconditional
// High-severity verdict (Count:0) with zero measurement - "un detecteur
// qui devine est pire qu'un controle absent". It no longer emits until
// that data is actually collected (see NewClient in
// internal/providers/smb/client.go for where a security-descriptor read
// would need to be added).
func (d *SysvolNetlogonDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	return nil
}

// No init()/MustRegister here - deliberately not
// wired into audit.DefaultRegistry. See Detect above.
