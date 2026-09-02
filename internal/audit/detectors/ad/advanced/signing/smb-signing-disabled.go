package signing

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SmbSigningDisabledDetector detects if SMB signing is disabled
type SmbSigningDisabledDetector struct {
	audit.BaseDetector
}

// NewSmbSigningDisabledDetector creates a new detector
func NewSmbSigningDisabledDetector() *SmbSigningDisabledDetector {
	return &SmbSigningDisabledDetector{
		BaseDetector: audit.NewBaseDetector("SMB_SIGNING_DISABLED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *SmbSigningDisabledDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "SMB Signing Not Required",
		Description: "SMB signing is not required on domain controllers, making the environment vulnerable to NTLM relay attacks.",
		Count:       0,
	}

	// SYSVOL unreachable (port 445 filtered, host down, ...) means
	// data.GPOPolicies is empty — we measured NOTHING, not "no GPO configures
	// signing". Firing here would flag every client that filters 445 between
	// the collector and its DCs, i.e. precisely the ones who hardened their
	// network (T_046/B_049 — the same "absence of measurement = negative
	// finding" bug T_019 fixed on Entra detectors and T_024 fixed on
	// permissions). A domain-local GPO always ships at least one parseable
	// security template, so a non-empty map is a reliable "SYSVOL was
	// reachable" signal.
	if len(data.GPOPolicies) == 0 {
		return []types.Finding{finding}
	}

	// Check GPO Registry.pol for RequireSecuritySignature (server)
	smbSigning := helpers.FindRegistrySettingInt(data.GPOPolicies, func(rs *audit.RegistrySettings) *int {
		return rs.RequireSMBSigningServer
	})

	if smbSigning != nil {
		if *smbSigning != 1 {
			finding.Count = 1
			finding.Details = map[string]interface{}{
				"currentValue":   *smbSigning,
				"requiredValue":  1,
				"recommendation": "Set 'Microsoft network server: Digitally sign communications (always)' to Enabled.",
			}
		}
	} else {
		// Measured (SYSVOL reachable, at least one policy parsed) but no
		// policy sets this key anywhere — Windows default (not required)
		// genuinely applies.
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"note":           "SYSVOL was reachable but no GPO configures SMB signing. Windows defaults do not require SMB signing.",
			"recommendation": "Configure 'Microsoft network server: Digitally sign communications (always)' via Group Policy.",
		}
	}

	if data.IncludeDetails && finding.Count > 0 && data.DomainInfo != nil {
		finding.AffectedEntities = []types.AffectedEntity{types.DomainInfoToAffectedEntity(data.DomainInfo)}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSmbSigningDisabledDetector())
}
