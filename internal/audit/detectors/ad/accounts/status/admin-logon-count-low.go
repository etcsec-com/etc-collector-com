package status

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// AdminLogonCountLowDetector detects admin accounts with low logon count
type AdminLogonCountLowDetector struct {
	audit.BaseDetector
}

// NewAdminLogonCountLowDetector creates a new detector
func NewAdminLogonCountLowDetector() *AdminLogonCountLowDetector {
	return &AdminLogonCountLowDetector{
		BaseDetector: audit.NewBaseDetector("ADMIN_LOGON_COUNT_LOW", audit.CategoryAccounts),
	}
}

// Detect executes the detection
//
// logonCount is documented by Microsoft Learn ("Logon-Count attribute",
// learn.microsoft.com/en-us/windows/win32/adschema/a-logoncount) as:
// "This attribute is not replicated and is maintained on each domain
// controller in the domain. To get an accurate value for the user's total
// number of successful logon attempts in the domain, each domain controller
// in the domain must be queried and the sum of the values should be used."
// The same page states plainly: "A value of 0 indicates that the value is
// unknown." So a value read from a single collected DC is, at best, that
// one DC's partial count - and 0 specifically is documented as unknown,
// not "zero logons ever". Treating either as proof that a domain-wide admin
// account is unused is not something the attribute supports on its own.
func (d *AdminLogonCountLowDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Must be enabled
		if u.Disabled {
			continue
		}
		// Must be marked as admin (adminCount = true)
		if !u.AdminCount {
			continue
		}
		// logonCount==0 is documented as "unknown", not "never logged on" -
		// treating it as a positive signal would be reading a "don't know"
		// as a "confirmed unused". Exclude it as inconclusive rather than
		// flag it.
		if u.LogonCount == 0 {
			continue
		}
		// A low but non-zero count on this one DC (less than 5). This is
		// still only a per-DC partial view, not a domain-wide total, so
		// treat it as a lead to investigate rather than confirmed evidence.
		if u.LogonCount < 5 {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityInfo,
		Category:    string(d.Category()),
		Title:       "Admin Account with Low Logon Count on This Domain Controller",
		Description: "Administrative accounts (adminCount=1) with fewer than 5 logons recorded on the domain controller queried. logonCount is a per-domain-controller counter that is never replicated (Microsoft Learn), so this is a partial, single-DC view, not a domain-wide total - accounts with logonCount=0 (documented as \"unknown\", not \"never logged on\") are excluded rather than treated as a signal. Treat matches as a lead for further investigation (e.g. querying every DC and summing), not as confirmed evidence of an unused account.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewAdminLogonCountLowDetector())
}
