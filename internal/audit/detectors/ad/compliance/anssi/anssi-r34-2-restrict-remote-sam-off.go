package anssi

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R34.2: RestrictRemoteSAM ---

type R342RestrictRemoteSAMDetector struct{ audit.BaseDetector }

func NewR342RestrictRemoteSAMDetector() *R342RestrictRemoteSAMDetector {
	return &R342RestrictRemoteSAMDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R34_2_RESTRICT_REMOTE_SAM_OFF", audit.CategoryCompliance)}
}
func (d *R342RestrictRemoteSAMDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	configured := false
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil || p.RegistrySettings.RestrictRemoteSAM == nil {
			continue
		}
		if *p.RegistrySettings.RestrictRemoteSAM != "" {
			configured = true
			break
		}
	}
	count := 0
	if !configured {
		count = 1
	}
	return wrapFinding(d, "ANSSI R34.2 - RestrictRemoteSAM non configuré",
		"ANSSI R34.2 (sub-reco) - SAM\\RestrictRemoteSam must be set to a SDDL allowing only admins. Without it, any domain user can enumerate local accounts via SAMR (Mimikatz / netsesh).",
		types.SeverityMedium, count, nil)
}

func init() {
	audit.MustRegister(NewR342RestrictRemoteSAMDetector())
}
