package gpo

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// PasswordInSysvolDetector checks for potential passwords in GPO SYSVOL
type PasswordInSysvolDetector struct {
	audit.BaseDetector
}

// NewPasswordInSysvolDetector creates a new detector
func NewPasswordInSysvolDetector() *PasswordInSysvolDetector {
	return &PasswordInSysvolDetector{
		BaseDetector: audit.NewBaseDetector("GPO_PASSWORD_IN_SYSVOL", audit.CategoryGPO),
	}
}

var riskyPatterns = []string{
	"password",
	"credential",
	"local admin",
	"service account",
	"scheduled task",
	"drive map",
}

// Detect executes the detection
func (d *PasswordInSysvolDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Passwords Found in GPO SYSVOL",
		Description: "GPO Preferences contain cleartext passwords in SYSVOL (cPassword vulnerability MS14-025). These passwords can be easily decrypted by any domain user.",
		Count:       0,
		Details: map[string]interface{}{
			"reference":   "MS14-025",
			"gposScanned": len(data.GPOs),
		},
	}

	// If SYSVOL scan data is available, use actual cpassword findings
	if len(data.SYSVOLFindings) > 0 {
		var cpasswordFindings []audit.SYSVOLFinding
		for _, sf := range data.SYSVOLFindings {
			if sf.Type == "cpassword" {
				cpasswordFindings = append(cpasswordFindings, sf)
			}
		}

		if len(cpasswordFindings) > 0 {
			finding.Count = len(cpasswordFindings)
			var details []string
			for _, cf := range cpasswordFindings {
				name := cf.GPOName
				if name == "" {
					name = cf.GPOGUID
				}
				details = append(details, fmt.Sprintf("%s: %s", name, cf.Details))
			}
			finding.Details["cpasswordFiles"] = details
			finding.Details["recommendation"] = "Remove cpassword entries from GPP XML files. Use LAPS or other secure credential management."
			if data.IncludeDetails {
				entities := make([]types.AffectedEntity, len(cpasswordFindings))
				for i, cf := range cpasswordFindings {
					ename := cf.GPOName
					if ename == "" {
						ename = cf.GPOGUID
					}
					entities[i] = types.AffectedEntity{Type: "gpo", Name: ename, DN: cf.GPOGUID}
				}
				finding.AffectedEntities = entities
			}
			return []types.Finding{finding}
		}
	}

	// Fallback: pattern-based detection on GPO names
	var affected []types.GPO
	for _, gpo := range data.GPOs {
		gpoName := strings.ToLower(gpo.DisplayName)
		if gpoName == "" {
			gpoName = strings.ToLower(gpo.CN)
		}
		for _, pattern := range riskyPatterns {
			if strings.Contains(gpoName, pattern) {
				affected = append(affected, gpo)
				break
			}
		}
	}

	finding.Count = len(affected)
	if len(affected) > 0 {
		finding.Description = "GPOs with names suggesting password storage detected. SYSVOL scan recommended to check for cleartext passwords (MS14-025)."
		if data.IncludeDetails {
			finding.AffectedEntities = helpers.ToAffectedGPOEntities(affected)
		}
		finding.Details["recommendation"] = "Scan SYSVOL for Groups.xml, Services.xml containing cpassword. Enable SMB collection for automatic detection."
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPasswordInSysvolDetector())
}
