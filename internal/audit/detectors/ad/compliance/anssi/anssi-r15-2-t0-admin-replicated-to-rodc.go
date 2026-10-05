package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- R57: T0 admins must NOT be in the RODC allow-replication list ---

type R152T0AdminInRODCDetector struct{ audit.BaseDetector }

func NewR152T0AdminInRODCDetector() *R152T0AdminInRODCDetector {
	return &R152T0AdminInRODCDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R15_2_T0_ADMIN_REPLICATED_TO_RODC", audit.CategoryCompliance)}
}
func (d *R152T0AdminInRODCDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build T0 DN set (Domain Admins, Enterprise Admins, Schema Admins members).
	t0 := map[string]bool{}
	for _, g := range data.Groups {
		sam := strings.ToLower(g.SAMAccountName)
		if sam == "domain admins" || sam == "enterprise admins" || sam == "schema admins" {
			for _, m := range g.Members {
				t0[strings.ToLower(m)] = true
			}
		}
	}
	count := 0
	for _, g := range data.Groups {
		if !strings.EqualFold(g.SAMAccountName, "Allowed RODC Password Replication Group") {
			continue
		}
		for _, m := range g.Members {
			if t0[strings.ToLower(m)] {
				count++
			}
		}
	}
	return wrapFinding(d, "ANSSI R57 - Admins T0 présents dans 'Allowed RODC Password Replication Group'",
		"ANSSI R57 (p.72) - Tier 0 administrators (Domain/Enterprise/Schema Admins) MUST NEVER be in the Allowed RODC Password Replication Group. Their hash on a physically-exposed RODC = instant golden ticket on RODC theft. (\"R15.2\" is a legacy internal label - PA-099 has no dotted sub-recommendation numbering; mappings.go already tags this ID against the real control, R57.)",
		types.SeverityCritical, count, nil)
}

func init() {
	audit.MustRegister(NewR152T0AdminInRODCDetector())
}
