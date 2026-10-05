package kerberos

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// KerberosRenewableTicketLongDetector checks for long renewable ticket
// lifetime.
//
// Source: Microsoft's own Default Domain Policy ships "Maximum lifetime for
// user ticket renewal" set to 7 days out of the box - the threshold this
// detector uses flags any domain that raised it above Microsoft's own
// default, not an arbitrary number.
//
// Known dead branch, not fixed here: the fallback below
// (data.DomainInfo.MaxRenewAge) is declared on the DomainInfo type but never
// assigned by any provider in this repo (confirmed by repo-wide grep - the
// only assignment of a MaxRenewAge field anywhere is
// audit.KerberosPolicy.MaxRenewAge, set by
// internal/providers/smb/gptmpl_parser.go from the real GptTmpl.inf policy,
// which is exactly the primary helpers.GetKerberosPolicy(data.GPOPolicies)
// path above). So today only that primary path can ever fire; the
// DomainInfo fallback is inert. Left in place (not deleted) in case a
// future provider populates DomainInfo.MaxRenewAge directly - deleting it
// here would silently drop that capability without any indication the
// removal happened.
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
