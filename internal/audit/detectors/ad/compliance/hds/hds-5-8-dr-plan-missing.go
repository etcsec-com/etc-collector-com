package hds

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- HDS - Plan de continuité (présence d'un backup AD documenté) ---

type HDS58DRPlanDetector struct{ audit.BaseDetector }

func NewHDS58DRPlanDetector() *HDS58DRPlanDetector {
	return &HDS58DRPlanDetector{BaseDetector: audit.NewBaseDetector("HDS_5_8_DR_PLAN_MISSING", audit.CategoryCompliance)}
}
func (d *HDS58DRPlanDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Heuristic: System State / NTBackup attribute present at the domain root?
	// In practice this is rarely populated in modern AD - rely on the
	// existence of at least 2 DCs (a single-DC forest fails DR by definition).
	dcCount := len(data.DomainControllers)
	count := 0
	if dcCount < 2 {
		count = 1
	}
	return wrap(d, "HDS - Plan de continuité AD insuffisant (heuristique)",
		fmt.Sprintf("A documented business continuity plan is a standard expectation of HDS-certified environments. Référentiel HDS Exigences V1.1.20221027 does not set this out as a specific numbered chapter-5 requirement (5.8 'Fonctionnement' is generic ISO 27001-style operational/risk-treatment planning, not a business-continuity mandate). HEURISTIC, not a direct measurement: this check uses domain-controller count as a rough, AD-observable proxy - a domain with %d co-located domain controller(s) and no real DR plan would still pass at >=2, while a well-planned single-DC deployment with off-domain backups still fails here. Treat as a prompt to verify manually, not a confirmed absence of continuity planning.", dcCount),
		types.SeverityHigh, count)
}

func init() {
	audit.MustRegister(NewHDS58DRPlanDetector())
}
