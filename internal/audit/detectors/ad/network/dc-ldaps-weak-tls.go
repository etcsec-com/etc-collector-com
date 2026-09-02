package network

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DcLdapsWeakTlsDetector detects DCs accepting weak TLS versions on LDAPS
type DcLdapsWeakTlsDetector struct {
	audit.BaseDetector
}

// NewDcLdapsWeakTlsDetector creates a new detector
func NewDcLdapsWeakTlsDetector() *DcLdapsWeakTlsDetector {
	return &DcLdapsWeakTlsDetector{
		BaseDetector: audit.NewBaseDetector("DC_LDAPS_WEAK_TLS", audit.CategoryNetwork),
	}
}

// Detect executes the detection
func (d *DcLdapsWeakTlsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "LDAPS Accepts Weak TLS Versions",
		Description: "Domain controllers accepting TLS 1.0 or 1.1 on LDAPS (port 636) are vulnerable to downgrade attacks and known TLS protocol vulnerabilities (POODLE, BEAST).",
	}

	if data.NetworkProbes == nil {
		return []types.Finding{finding}
	}

	var affected []string
	for _, result := range data.NetworkProbes.TLSResults {
		if result.WeakTLS {
			affected = append(affected, result.DCHostname)
		}
	}

	finding.Count = len(affected)
	if data.IncludeDetails && len(affected) > 0 {
		finding.Details = map[string]interface{}{
			"affectedDCs":    affected,
			"recommendation": "Disable TLS 1.0 and TLS 1.1 on all domain controllers via registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDcLdapsWeakTlsDetector())
}
