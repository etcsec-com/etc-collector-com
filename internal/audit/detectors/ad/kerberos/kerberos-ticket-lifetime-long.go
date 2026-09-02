package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// KerberosTicketLifetimeLongDetector checks for long Kerberos ticket lifetime
type KerberosTicketLifetimeLongDetector struct {
	audit.BaseDetector
}

// NewKerberosTicketLifetimeLongDetector creates a new detector
func NewKerberosTicketLifetimeLongDetector() *KerberosTicketLifetimeLongDetector {
	return &KerberosTicketLifetimeLongDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROS_TICKET_LIFETIME_LONG", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *KerberosTicketLifetimeLongDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Kerberos Ticket Lifetime Too Long",
		Description: "Kerberos TGT lifetime exceeds recommended 10 hours, increasing the attack window for stolen tickets.",
		Count:       0,
	}

	maxTicketAge := 0

	// Try SYSVOL GPO data first
	kp := helpers.GetKerberosPolicy(data.GPOPolicies)
	if kp != nil && kp.MaxTicketAge > 0 {
		maxTicketAge = kp.MaxTicketAge
	} else if data.DomainInfo != nil && data.DomainInfo.MaxTicketAge > 0 {
		// Fallback to LDAP DomainInfo
		maxTicketAge = data.DomainInfo.MaxTicketAge
	}

	if maxTicketAge > 10 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"maxTicketAge":   maxTicketAge,
			"recommendedMax": 10,
			"unit":           "hours",
			"recommendation": "Set TGT maximum lifetime to 10 hours or less in Default Domain Policy.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewKerberosTicketLifetimeLongDetector())
}
