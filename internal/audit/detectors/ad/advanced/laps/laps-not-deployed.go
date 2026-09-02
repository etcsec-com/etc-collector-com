package laps

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LapsNotDeployedDetector reports, at DOMAIN level, that no machine in the
// domain has a LAPS-managed local administrator password.
//
// T_036 — this used to emit the per-machine list, i.e. the same 72 computers
// COMPUTER_NO_LAPS already reports, so a customer saw the same gap twice (three
// times with LAPS_DOMAIN_COVERAGE_LOW). Under the granularity rule
// (detectors/ad/dedup.go, R2) the per-machine list belongs to COMPUTER_NO_LAPS
// alone; this detector answers the binary domain-level question "is LAPS
// deployed at all here?", which the per-machine list cannot express — a domain
// with zero coverage is a different conversation from one with a few gaps.
//
// It was repurposed rather than deleted because it is the ONLY detector mapping
// ANSSI BP-039 R12 and PA-099 R30- (dedup.go, R4): deleting it would have
// silently removed two controls from the compliance score.
//
// Its predicate also changed: it tested LegacyLAPSPassword/WindowsLAPSPassword,
// the password VALUE fields, which are only populated when the audit account
// can READ the password — and LegacyLAPSPassword is never populated at all
// (ldap/parser.go writes the legacy attribute into LAPSPassword). It therefore
// counted "machines whose LAPS password I could not read" — 74, i.e. every
// computer including the DCs and the disabled ones. It now uses the presence
// booleans, derived from the expiry attributes, which any authenticated account
// can read.
type LapsNotDeployedDetector struct {
	audit.BaseDetector
}

// NewLapsNotDeployedDetector creates a new detector
func NewLapsNotDeployedDetector() *LapsNotDeployedDetector {
	return &LapsNotDeployedDetector{
		BaseDetector: audit.NewBaseDetector("LAPS_NOT_DEPLOYED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *LapsNotDeployedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	const serverTrustAccount = 0x2000 // DC flag

	eligible, covered := 0, 0
	for _, c := range data.Computers {
		// Same population as COMPUTER_NO_LAPS: enabled, non-DC machines.
		if c.Disabled || (c.UserAccountControl&serverTrustAccount) != 0 {
			continue
		}
		eligible++
		if c.HasLegacyLAPS || c.HasWindowsLAPS {
			covered++
		}
	}

	// Nothing to say when there is no machine to protect, or when at least one
	// is covered — partial coverage is LAPS_DOMAIN_COVERAGE_LOW's subject.
	count := 0
	if eligible > 0 && covered == 0 {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "LAPS Not Deployed (domain-wide)",
		Description: "No computer in the domain has a LAPS-managed local administrator password. Local admin credentials are shared or static across the estate, so one compromised machine yields lateral movement to all of them.",
		Count:       count,
	}

	if count > 0 {
		finding.Details = map[string]interface{}{
			"eligibleComputers": eligible,
			"coveredComputers":  covered,
			"scope":             "domain",
			"perMachineFinding": "COMPUTER_NO_LAPS",
			"recommendation":    fmt.Sprintf("Deploy Windows LAPS to the %d eligible computers; the per-machine list is reported by COMPUTER_NO_LAPS.", eligible),
		}
		if data.IncludeDetails {
			// Domain-level statement → the domain is the affected entity. The
			// machines themselves are listed once, by COMPUTER_NO_LAPS.
			if data.DomainInfo != nil && data.DomainInfo.DomainDN != "" {
				finding.AffectedEntities = []types.AffectedEntity{data.EntityForDN(data.DomainInfo.DomainDN)}
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLapsNotDeployedDetector())
}
