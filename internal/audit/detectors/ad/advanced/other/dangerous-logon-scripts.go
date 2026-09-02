package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DangerousLogonScriptsDetector detects dangerous logon scripts
type DangerousLogonScriptsDetector struct {
	audit.BaseDetector
}

// NewDangerousLogonScriptsDetector creates a new detector
func NewDangerousLogonScriptsDetector() *DangerousLogonScriptsDetector {
	return &DangerousLogonScriptsDetector{
		BaseDetector: audit.NewBaseDetector("DANGEROUS_LOGON_SCRIPTS", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *DangerousLogonScriptsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Check if user has logon script configured pointing to network path
		if u.ScriptPath != "" {
			if strings.Contains(u.ScriptPath, "\\\\") || strings.HasPrefix(u.ScriptPath, "//") {
				affected = append(affected, u)
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Dangerous Logon Scripts",
		Description: "Logon scripts with weak ACLs can be modified by attackers for code execution on user login.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousLogonScriptsDetector())
}
