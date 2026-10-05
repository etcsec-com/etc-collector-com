package domainpolicy

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WeakKerberosPolicyDetector detects weak Kerberos policy settings
type WeakKerberosPolicyDetector struct {
	audit.BaseDetector
}

// NewWeakKerberosPolicyDetector creates a new detector
func NewWeakKerberosPolicyDetector() *WeakKerberosPolicyDetector {
	return &WeakKerberosPolicyDetector{
		BaseDetector: audit.NewBaseDetector("WEAK_KERBEROS_POLICY", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *WeakKerberosPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return []types.Finding{{
			Type:        d.ID(),
			Severity:    types.SeverityMedium,
			Category:    string(d.Category()),
			Title:       "Weak Kerberos Policy",
			Description: "Unable to check Kerberos policy.",
			Count:       0,
		}}
	}

	// data.DomainInfo.MaxTicketAge/MaxRenewAge are never
	// assigned by any provider - the real write lands on
	// audit.KerberosPolicy via SYSVOL GptTmpl.inf parsing, a different
	// struct. Read via the same path the sibling detectors
	// (KERBEROS_TICKET_LIFETIME_LONG, KERBEROS_RENEWABLE_TICKET_LONG)
	// already use: helpers.GetKerberosPolicy(data.GPOPolicies), falling
	// back to DomainInfo.
	maxTicketAge := 0
	maxRenewAge := 0
	if kp := helpers.GetKerberosPolicy(data.GPOPolicies); kp != nil {
		if kp.MaxTicketAge > 0 {
			maxTicketAge = kp.MaxTicketAge
		}
		if kp.MaxRenewAge > 0 {
			maxRenewAge = kp.MaxRenewAge
		}
	}
	if maxTicketAge == 0 && data.DomainInfo.MaxTicketAge > 0 {
		maxTicketAge = data.DomainInfo.MaxTicketAge
	}
	if maxRenewAge == 0 && data.DomainInfo.MaxRenewAge > 0 {
		maxRenewAge = data.DomainInfo.MaxRenewAge
	}

	// Weak if ticket age > 10 hours or renew age > 7 days
	isWeak := maxTicketAge > 10 || maxRenewAge > 7

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Weak Kerberos Policy",
		Description: "Kerberos ticket lifetimes exceed recommended values. Longer window for ticket-based attacks.",
		Count:       0,
	}

	if isWeak {
		finding.Count = 1
		if data.IncludeDetails {
			finding.AffectedEntities = []types.AffectedEntity{types.DomainInfoToAffectedEntity(data.DomainInfo)}
			finding.Details = map[string]interface{}{
				"maxTicketAge": maxTicketAge,
				"maxRenewAge":  maxRenewAge,
			}
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWeakKerberosPolicyDetector())
}
