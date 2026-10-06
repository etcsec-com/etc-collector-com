package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AsrepRoastingOnDisabledAccountDetector checks for disabled accounts without
// Kerberos pre-authentication. Split out of AsrepRoastingRiskDetector: the KDC
// rejects the AS-REQ on account status before pre-authentication is ever
// considered, so these accounts are not exploitable today - but the bit
// persists on disk and would matter again the moment the account is
// re-enabled, so it stays reported, at a severity that reflects dormancy
// rather than active risk.
//
// Named ASREP_ROASTING_ON_DISABLED_ACCOUNT, not ASREP_ROASTING_DISABLED: the
// _DISABLED suffix is reserved elsewhere in this catalog for "a protection was
// turned off" (LDAP_SIGNING_DISABLED, TRUST_AES_DISABLED, ...), which reads as
// bad news. Naming the population instead of a mechanism state avoids an
// auditor misreading this as the risk itself being off.
type AsrepRoastingOnDisabledAccountDetector struct {
	audit.BaseDetector
}

// NewAsrepRoastingOnDisabledAccountDetector creates a new detector
func NewAsrepRoastingOnDisabledAccountDetector() *AsrepRoastingOnDisabledAccountDetector {
	return &AsrepRoastingOnDisabledAccountDetector{
		BaseDetector: audit.NewBaseDetector("ASREP_ROASTING_ON_DISABLED_ACCOUNT", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *AsrepRoastingOnDisabledAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, user := range data.Users {
		if !user.Disabled {
			continue
		}
		if (user.UserAccountControl & types.UACDontRequirePreauth) != 0 {
			affected = append(affected, user)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "AS-REP Roasting Risk (Disabled Account)",
		Description: "Disabled user accounts without Kerberos pre-authentication required (UAC 0x400000). Not exploitable while disabled - the KDC rejects the AS-REQ on account status first - but the bit remains set and would apply again if the account is re-enabled.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAsrepRoastingOnDisabledAccountDetector())
}
