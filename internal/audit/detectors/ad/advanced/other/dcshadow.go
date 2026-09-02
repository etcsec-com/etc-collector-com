package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DCShadowDetector detects evidence of DCShadow attacks
type DCShadowDetector struct {
	audit.BaseDetector
}

// NewDCShadowDetector creates a new detector
func NewDCShadowDetector() *DCShadowDetector {
	return &DCShadowDetector{
		BaseDetector: audit.NewBaseDetector("DCSHADOW_EVIDENCE", audit.CategoryAdvanced),
	}
}

// uacServerTrustAccountFlag is the UAC flag for SERVER_TRUST_ACCOUNT (domain controller)
const uacServerTrustAccountFlag = 0x2000

// Detect executes the detection
func (d *DCShadowDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	// Check DomainControllers for any DC outside the standard Domain Controllers OU
	for _, dc := range data.DomainControllers {
		if !isInDomainControllersOU(dc.DistinguishedName) && !isInDomainControllersOU(dc.DN) {
			affected = append(affected, dc)
		}
	}

	// Also check Computers for SERVER_TRUST_ACCOUNT outside Domain Controllers OU
	seen := make(map[string]bool)
	for _, dc := range affected {
		if dc.DN != "" {
			seen[dc.DN] = true
		}
		if dc.DistinguishedName != "" {
			seen[dc.DistinguishedName] = true
		}
	}

	for _, computer := range data.Computers {
		if (computer.UserAccountControl & uacServerTrustAccountFlag) == 0 {
			continue
		}

		dn := computer.DistinguishedName
		if dn == "" {
			dn = computer.DN
		}

		if seen[dn] {
			continue
		}

		if !isInDomainControllersOU(dn) {
			affected = append(affected, computer)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Evidence of Mimikatz DCShadow Attack",
		Description: "Domain Controller objects detected outside the standard Domain Controllers OU. This may indicate a DCShadow attack where rogue DCs were registered to inject malicious changes into the directory via replication.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

// isInDomainControllersOU checks if the DN contains the standard Domain Controllers OU
func isInDomainControllersOU(dn string) bool {
	return strings.Contains(strings.ToLower(dn), "ou=domain controllers")
}

func init() {
	audit.MustRegister(NewDCShadowDetector())
}
