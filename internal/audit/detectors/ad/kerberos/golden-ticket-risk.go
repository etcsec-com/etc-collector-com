package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GoldenTicketRiskDetector checks for krbtgt account with old password
type GoldenTicketRiskDetector struct {
	audit.BaseDetector
}

// NewGoldenTicketRiskDetector creates a new detector
func NewGoldenTicketRiskDetector() *GoldenTicketRiskDetector {
	return &GoldenTicketRiskDetector{
		BaseDetector: audit.NewBaseDetector("GOLDEN_TICKET_RISK", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *GoldenTicketRiskDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var krbtgtAccount *types.User

	for i := range data.Users {
		if data.Users[i].SAMAccountName == "krbtgt" {
			krbtgtAccount = &data.Users[i]
			break
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Golden Ticket Risk",
		Description: "krbtgt account password unchanged for 180+ days. Enables persistent Golden Ticket attacks.",
		Count:       0,
	}

	if krbtgtAccount == nil || krbtgtAccount.PasswordLastSet.IsZero() {
		finding.Description = "krbtgt account password unchanged for 180+ days or password date unavailable. Enables persistent Golden Ticket attacks."
		return []types.Finding{finding}
	}

	sixMonthsAgo := data.Now.AddDate(0, -6, 0)
	isOld := krbtgtAccount.PasswordLastSet.Before(sixMonthsAgo)

	if isOld {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedUserEntities([]types.User{*krbtgtAccount})
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGoldenTicketRiskDetector())
}
