package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// KerberosRenewableTicketLongDetector checks for long renewable ticket lifetime
type KerberosRenewableTicketLongDetector struct {
	audit.BaseDetector
}

// NewKerberosRenewableTicketLongDetector creates a new detector
func NewKerberosRenewableTicketLongDetector() *KerberosRenewableTicketLongDetector {
	return &KerberosRenewableTicketLongDetector{
		BaseDetector: audit.NewBaseDetector("KERBEROS_RENEWABLE_TICKET_LONG", audit.CategoryKerberos),
	}
}

// Detect executes the detection
func (d *KerberosRenewableTicketLongDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "Kerberos Renewable Ticket Lifetime Too Long",
		Description: "Renewable ticket lifetime exceeds recommended 7 days, allowing persistent access with stolen tickets.",
		Count:       0,
	}

	maxRenewAge := 0

	kp := helpers.GetKerberosPolicy(data.GPOPolicies)
	if kp != nil && kp.MaxRenewAge > 0 {
		maxRenewAge = kp.MaxRenewAge
	} else if data.DomainInfo != nil && data.DomainInfo.MaxRenewAge > 0 {
		maxRenewAge = data.DomainInfo.MaxRenewAge
	}

	if maxRenewAge > 7 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"maxRenewAge":    maxRenewAge,
			"recommendedMax": 7,
			"unit":           "days",
			"recommendation": "Set maximum renewable ticket lifetime to 7 days or less in Default Domain Policy.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewKerberosRenewableTicketLongDetector())
}
