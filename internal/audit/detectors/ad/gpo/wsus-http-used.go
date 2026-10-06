package gpo

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// WSUSHTTPDetector checks if WSUS is configured over HTTP instead of HTTPS
type WSUSHTTPDetector struct {
	audit.BaseDetector
}

func NewWSUSHTTPDetector() *WSUSHTTPDetector {
	return &WSUSHTTPDetector{
		BaseDetector: audit.NewBaseDetector("WSUS_HTTP_USED", audit.CategoryGPO),
	}
}

func (d *WSUSHTTPDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "WSUS Configured Over HTTP",
		Description: "Windows Server Update Services (WSUS) is configured to use HTTP instead of HTTPS. This allows attackers on the network to perform man-in-the-middle attacks and inject malicious updates, achieving code execution on all domain-joined machines.",
		Count:       0,
	}

	v := helpers.FindRegistrySettingString(data.GPOPolicies, func(rs *audit.RegistrySettings) *string {
		return rs.WUServer
	})

	// Source: Microsoft Learn, "Configure Automatic Updates" Group Policy
	// (Computer Configuration > Administrative Templates > Windows
	// Components > Windows Update, "Specify intranet Microsoft update
	// service location"). Enabling it writes the intranet WSUS URL as
	// WUServer (REG_SZ) under
	// HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate - an
	// unencrypted http:// URL lets an on-path attacker serve unsigned
	// update metadata/binaries to every domain-joined client pointed at
	// that server (WSUS itself does not require HTTPS by default; Microsoft
	// recommends configuring SSL). https:// (or no WUServer configured, i.e.
	// clients use public Windows Update instead) is safe.
	if v != nil && strings.HasPrefix(strings.ToLower(*v), "http://") {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"wsusURL":        *v,
			"recommendation": "Configure WSUS to use HTTPS and enable SSL on the WSUS server.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewWSUSHTTPDetector())
}
