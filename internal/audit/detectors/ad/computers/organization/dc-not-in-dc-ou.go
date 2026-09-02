package organization

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DCNotInDCOUDetector detects DCs not in Domain Controllers OU
type DCNotInDCOUDetector struct {
	audit.BaseDetector
}

// NewDCNotInDCOUDetector creates a new detector
func NewDCNotInDCOUDetector() *DCNotInDCOUDetector {
	return &DCNotInDCOUDetector{
		BaseDetector: audit.NewBaseDetector("DC_NOT_IN_DC_OU", audit.CategoryComputers),
	}
}

// UAC flag for server trust account (DC)
const uacServerTrustAccount = 0x2000

// Detect executes the detection
func (d *DCNotInDCOUDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer
	dcPattern := regexp.MustCompile(`(?i)^DC\d*`)

	for _, c := range data.Computers {
		// Check if it's a domain controller
		isDC := dcPattern.MatchString(c.SAMAccountName) ||
			strings.Contains(strings.ToLower(c.DNSHostName), "dc") ||
			(c.UserAccountControl&uacServerTrustAccount) != 0

		if !isDC {
			continue
		}

		// Check if it's in the Domain Controllers OU
		isInDCOU := strings.Contains(strings.ToLower(c.DistinguishedName), "ou=domain controllers")

		if !isInDCOU {
			affected = append(affected, c)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Domain Controller Not in Domain Controllers OU",
		Description: "Domain Controllers found outside the Domain Controllers OU. This may indicate misconfiguration or an attempt to hide a rogue DC.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}
	if len(affected) > 0 {
		finding.Details = map[string]interface{}{
			"recommendation": "Move all Domain Controllers to the Domain Controllers OU for proper GPO application and management.",
			"risks": []string{
				"GPOs targeting Domain Controllers OU may not apply",
				"May indicate rogue or compromised DC",
				"Security baselines may not be applied correctly",
			},
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDCNotInDCOUDetector())
}
