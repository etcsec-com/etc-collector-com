package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AsrepRoastingRiskDetector checks for accounts without Kerberos pre-authentication
type AsrepRoastingRiskDetector struct {
	audit.BaseDetector
}

// NewAsrepRoastingRiskDetector creates a new detector
func NewAsrepRoastingRiskDetector() *AsrepRoastingRiskDetector {
	return &AsrepRoastingRiskDetector{
		BaseDetector: audit.NewBaseDetector("ASREP_ROASTING_RISK", audit.CategoryKerberos),
	}
}

// Detect executes the detection
//
// Disabled accounts are excluded here on purpose: the KDC rejects the AS-REQ
// on account status before pre-authentication is ever considered, so a
// disabled account carrying this bit is not exploitable today. It is not
// dropped from the audit - AsrepRoastingOnDisabledAccountDetector reports it at Low,
// since the bit persists and would matter again the moment the account is
// re-enabled.
func (d *AsrepRoastingRiskDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if user.Disabled {
			continue
		}
		if (user.UserAccountControl & types.UACDontRequirePreauth) != 0 {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "AS-REP Roasting Risk",
		Description: "Enabled user accounts without Kerberos pre-authentication required (UAC 0x400000). Vulnerable to AS-REP roasting attacks today.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAsrepRoastingRiskDetector())
}
