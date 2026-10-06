package monitoring

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// HoneypotAccountsDetector checks for absence of honeypot/decoy accounts
type HoneypotAccountsDetector struct {
	audit.BaseDetector
}

// NewHoneypotAccountsDetector creates a new detector
func NewHoneypotAccountsDetector() *HoneypotAccountsDetector {
	return &HoneypotAccountsDetector{
		BaseDetector: audit.NewBaseDetector("NO_HONEYPOT_ACCOUNTS", audit.CategoryMonitoring),
	}
}

var honeypotPatterns = []string{"honeypot", "decoy", "trap", "canary", "bait", "fake"}

// Detect executes the detection
func (d *HoneypotAccountsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var honeypots []string

	for _, user := range data.Users {
		nameLower := strings.ToLower(user.SAMAccountName)
		descLower := strings.ToLower(user.Description)

		matchesMarker := false
		for _, pattern := range honeypotPatterns {
			if strings.Contains(descLower, pattern) || strings.Contains(nameLower, pattern) {
				matchesMarker = true
				break
			}
		}
		if !matchesMarker {
			continue
		}

		// A deliberate decoy is set up and never touched. A generic-sounding
		// service account name is not, on its own, evidence of a honeypot -
		// real, actively-used service accounts routinely look "attractive"
		// (svc_sql, svc_backup, backup_admin) without being decoys.
		if user.LastLogon.IsZero() && !user.Disabled {
			honeypots = append(honeypots, user.SAMAccountName)
		}
	}

	hasHoneypots := len(honeypots) > 0

	count := 0
	if !hasHoneypots {
		count = 1
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "No Honeypot/Decoy Accounts Detected",
		Description: "No honeypot or decoy accounts detected in the directory. These accounts help detect attackers during enumeration phase.",
		Count:       count,
	}

	if hasHoneypots {
		finding.Details = map[string]interface{}{
			"honeypotCount": len(honeypots),
			"status":        "Honeypot accounts detected",
		}
	} else {
		finding.Details = map[string]interface{}{
			"recommendation": "Create honeypot accounts with attractive names (e.g., svc_backup, admin_old) and monitor for any usage.",
			"benefits": []string{
				"Early detection of attacker enumeration",
				"Detect credential stuffing attempts",
				"Alert on lateral movement",
			},
			"implementationGuide": "Create accounts with attractive names but no real permissions. Alert on any authentication attempt.",
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewHoneypotAccountsDetector())
}
