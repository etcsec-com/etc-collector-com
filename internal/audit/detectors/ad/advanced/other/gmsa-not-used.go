package other

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// GMSANotInUseDetector detects domains not using gMSA despite having service accounts
type GMSANotInUseDetector struct {
	audit.BaseDetector
}

// NewGMSANotInUseDetector creates a new detector
func NewGMSANotInUseDetector() *GMSANotInUseDetector {
	return &GMSANotInUseDetector{
		BaseDetector: audit.NewBaseDetector("GMSA_NOT_IN_USE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *GMSANotInUseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	gmsaCount := 0
	serviceAccountsWithSPN := 0

	for _, user := range data.Users {
		if user.IsGMSA {
			gmsaCount++
		}

		if !user.Disabled && len(user.ServicePrincipalNames) > 0 {
			serviceAccountsWithSPN++
		}
	}

	count := 0
	if gmsaCount == 0 && serviceAccountsWithSPN > 0 {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Group Managed Service Accounts (gMSA) Not in Use",
		Description: "No Group Managed Service Accounts (gMSA) are deployed in the domain despite having service accounts with SPNs. gMSA provides automatic password management and eliminates the risk of stale service account passwords.",
		Count:       count,
		Details: map[string]interface{}{
			"serviceAccountsWithSPN": serviceAccountsWithSPN,
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewGMSANotInUseDetector())
}
