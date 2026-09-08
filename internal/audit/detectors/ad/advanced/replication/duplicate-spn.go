package replication

import (
	"context"
	"sort"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DuplicateSpnDetector detects duplicate SPNs
type DuplicateSpnDetector struct {
	audit.BaseDetector
}

// NewDuplicateSpnDetector creates a new detector
func NewDuplicateSpnDetector() *DuplicateSpnDetector {
	return &DuplicateSpnDetector{
		BaseDetector: audit.NewBaseDetector("DUPLICATE_SPN", audit.CategoryAdvanced),
	}
}

// Detect executes the detection.
//
// Source: Microsoft Learn, "Setspn" (learn.microsoft.com/en-us/windows-server/
// administration/windows-commands/setspn), Remarks section: "SPNs aren't case
// sensitive when used by Microsoft Windows-based computers." Two SPNs that
// differ only by case are the same registration as far as Windows/Kerberos
// is concerned, so the comparison below is done on a case-folded key
// (matching the case-insensitive comparison already used by the sibling
// COMPUTER_DUPLICATE_SPN detector) to avoid missing real duplicates.
func (d *DuplicateSpnDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Build SPN to DN mapping. Keys are case-folded (strings.ToLower) because
	// SPNs are not case sensitive on Windows Server - see source above.
	spnMap := make(map[string][]string)

	for _, u := range data.Users {
		for _, spn := range u.ServicePrincipalNames {
			key := strings.ToLower(spn)
			spnMap[key] = append(spnMap[key], u.DN)
		}
	}

	for _, c := range data.Computers {
		for _, spn := range c.ServicePrincipalNames {
			key := strings.ToLower(spn)
			spnMap[key] = append(spnMap[key], c.DN)
		}
	}

	// Find duplicate SPNs. SPN keys sorted: spnMap is a map, so
	// ranging it directly gives a randomized order per process - same input,
	// different JSON, different sha256 across runs.
	spns := make([]string, 0, len(spnMap))
	for spn := range spnMap {
		spns = append(spns, spn)
	}
	sort.Strings(spns)

	var affectedDNs []string
	for _, spn := range spns {
		dns := spnMap[spn]
		if len(dns) > 1 {
			affectedDNs = append(affectedDNs, dns...)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Duplicate SPN",
		Description: "A Service Principal Name is registered on more than one account (compared case-insensitively, since SPNs are not case sensitive on Windows Server). Can cause Kerberos authentication failures against the wrong account. Count is the number of accounts (distinguished names) that hold a duplicated SPN, not the number of distinct duplicated SPN values - e.g. one SPN shared by two accounts yields Count=2.",
		Count:       len(affectedDNs),
	}

	if data.IncludeDetails && len(affectedDNs) > 0 {
		seen := make(map[string]bool, len(affectedDNs))
		entities := make([]types.AffectedEntity, 0, len(affectedDNs))
		for _, dn := range affectedDNs {
			if seen[dn] {
				continue
			}
			seen[dn] = true
			entities = append(entities, data.EntityForDN(dn))
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDuplicateSpnDetector())
}
