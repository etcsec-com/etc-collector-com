package adcs

import (
	"context"
	"fmt"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC8Detector detects ESC8: NTLM Relay to AD CS HTTP Endpoint
type ESC8Detector struct {
	audit.BaseDetector
}

// NewESC8Detector creates a new detector
func NewESC8Detector() *ESC8Detector {
	return &ESC8Detector{
		BaseDetector: audit.NewBaseDetector("ESC8_HTTP_ENROLLMENT", audit.CategoryADCS),
	}
}

// Detect executes the detection
func (d *ESC8Detector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "ESC8 - HTTP Web Enrollment Enabled",
		Description: "Certificate Authority web enrollment is accessible over HTTP, enabling NTLM relay attacks against certificate enrollment.",
		Count:       0,
	}

	// If network probes are not enabled, we can't detect this
	if data.NetworkProbes == nil {
		finding.Details = map[string]interface{}{
			"note": "Enable network probes (--enable-network-probes + networkProbes:true) to detect HTTP web enrollment endpoints.",
		}
		return []types.Finding{finding}
	}

	var vulnerableHosts []string
	var notDetermined []string
	for _, r := range data.NetworkProbes.ESC8Results {
		switch {
		case r.WebEnrollment:
			vulnerableHosts = append(vulnerableHosts, fmt.Sprintf("%s (HTTP %d)", r.CAHostname, r.StatusCode))
		case !r.Determined:
			notDetermined = append(notDetermined, r.CAHostname)
		}
	}

	if len(vulnerableHosts) > 0 || len(notDetermined) > 0 {
		finding.Count = len(vulnerableHosts)
		details := map[string]interface{}{}
		if len(vulnerableHosts) > 0 {
			details["vulnerableEndpoints"] = vulnerableHosts
			details["recommendation"] = "Disable HTTP enrollment or require HTTPS with Extended Protection for Authentication."
		}
		if len(notDetermined) > 0 {
			details["notDetermined"] = notDetermined
			details["notDeterminedReason"] = "HTTP probe could not reach these hosts (e.g. hostname did not resolve) - ESC8 exposure could not be tested"
		}
		finding.Details = details
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewESC8Detector())
}
