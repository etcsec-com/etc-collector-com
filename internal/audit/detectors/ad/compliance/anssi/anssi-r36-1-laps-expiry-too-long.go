package anssi

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// --- LAPS password expiry too long ---
//
// "R36.1" never existed: PA-099 has no dotted sub-recommendation
// numbering at all (verified: zero "R\d+\.\d+" matches anywhere in the
// published v1.0 PDF), and R36 itself is "Traiter les risques inhérents aux
// IGC qui pèsent sur le Tier 0" (CA/PKI risk, unrelated to LAPS). The real
// LAPS recommendation is R30 ("Diversifier et renouveler automatiquement les
// mots de passe des comptes admin locaux", p.48): it requires deploying an
// automatic local-admin-password rotation solution (LAPS or equivalent) but
// - checked against the full body text of R30 - specifies NO numeric
// rotation-interval threshold. mappings.go already tags this detector ID
// against PA-099 R30, not R36.
//
// 30 days is the well-known default PasswordAgeDays of legacy Microsoft
// LAPS, not an ANSSI-mandated number: it's used here as an etc-collector
// product benchmark for "rotation interval too long", same category as
// daCountBenchmark in r2-privileged-accounts.go.
//
// v3.1.19 - REWRITE: real check based on Computer.LAPSPasswordExpiry,
// populated from ms-Mcs-AdmPwdExpirationTime (legacy) or
// msLAPS-PasswordExpirationTime (modern Windows LAPS).

type R361LAPSExpiryDetector struct{ audit.BaseDetector }

func NewR361LAPSExpiryDetector() *R361LAPSExpiryDetector {
	return &R361LAPSExpiryDetector{BaseDetector: audit.NewBaseDetector("ANSSI_R36_1_LAPS_EXPIRY_TOO_LONG", audit.CategoryCompliance)}
}

// lapsMaxExpiryDaysBenchmark is the legacy Microsoft LAPS default
// PasswordAgeDays, used as an etc-collector product benchmark - PA-099 R30
// requires automatic local-admin-password rotation but specifies no
// numeric interval.
const lapsMaxExpiryDaysBenchmark = 30

func (d *R361LAPSExpiryDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	threshold := data.Now.AddDate(0, 0, lapsMaxExpiryDaysBenchmark)
	var stale []types.Computer
	for _, c := range data.Computers {
		if c.LAPSPasswordExpiry.IsZero() {
			continue // computer outside LAPS scope - not in scope of this check
		}
		if c.LAPSPasswordExpiry.After(threshold) {
			stale = append(stale, c)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	return wrapFinding(d, "LAPS password expiry beyond product benchmark (30 days)",
		fmt.Sprintf("ANSSI PA-099 R30 requires an automatic local-admin-password rotation solution (LAPS or equivalent) but specifies no rotation-interval number. %d computer(s) currently have a LAPS expiry timestamp more than %d days in the future - beyond the legacy LAPS default and etc-collector's product benchmark for 'rotation interval too long'. Reduce the LAPS GPO PasswordAgeDays to %d (or lower).", len(stale), lapsMaxExpiryDaysBenchmark, lapsMaxExpiryDaysBenchmark),
		types.SeverityMedium, len(stale), computersToEntities(stale, data.IncludeDetails))
}

func init() {
	audit.MustRegister(NewR361LAPSExpiryDetector())
}
