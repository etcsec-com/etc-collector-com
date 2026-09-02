package security

import (
	"context"
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DuplicateSpnDetector checks for duplicate SPNs across computers
type DuplicateSpnDetector struct {
	audit.BaseDetector
}

// NewDuplicateSpnDetector creates a new detector
func NewDuplicateSpnDetector() *DuplicateSpnDetector {
	return &DuplicateSpnDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_DUPLICATE_SPN", audit.CategoryComputers),
	}
}

// Detect executes the detection
func (d *DuplicateSpnDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build SPN to computer mapping
	spnMap := make(map[string][]types.Computer)

	for _, c := range data.Computers {
		if len(c.ServicePrincipalNames) == 0 {
			continue
		}

		for _, spn := range c.ServicePrincipalNames {
			normalizedSPN := strings.ToLower(spn)
			spnMap[normalizedSPN] = append(spnMap[normalizedSPN], c)
		}
	}

	// Find computers with duplicate SPNs
	duplicateComputers := make(map[string]types.Computer)

	for _, computers := range spnMap {
		if len(computers) > 1 {
			for _, c := range computers {
				duplicateComputers[c.DN] = c
			}
		}
	}

	// Convert map to slice. Sorted by DN (T_046/B_048): ranging a map gives a
	// randomized order per process, which made two audits of the exact same
	// input serialize to different JSON (different sha256).
	affected := make([]types.Computer, 0, len(duplicateComputers))
	for _, c := range duplicateComputers {
		affected = append(affected, c)
	}
	sort.Slice(affected, func(i, j int) bool { return affected[i].DN < affected[j].DN })

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Duplicate SPNs Detected",
		Description: "Multiple computers share the same Service Principal Name. This causes Kerberos authentication failures.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDuplicateSpnDetector())
}
