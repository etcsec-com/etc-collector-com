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
var attractivePatterns = []string{"svc_", "admin_backup", "admin_old", "sa_", "sqlsvc", "backup_admin"}

// Detect executes the detection
func (d *HoneypotAccountsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var honeypots []string
	var potentialBaits []string

	for _, user := range data.Users {
		nameLower := strings.ToLower(user.SAMAccountName)
		descLower := strings.ToLower(user.Description)

		// Find explicit honeypot accounts
		for _, pattern := range honeypotPatterns {
			if strings.Contains(descLower, pattern) || strings.Contains(nameLower, pattern) {
				honeypots = append(honeypots, user.SAMAccountName)
				break
			}
		}

		// Find potential bait accounts (attractive names, never used)
		for _, pattern := range attractivePatterns {
			if strings.Contains(nameLower, pattern) {
				if user.LastLogon.IsZero() && !user.Disabled {
					potentialBaits = append(potentialBaits, user.SAMAccountName)
				}
				break
			}
		}
	}

	hasHoneypots := len(honeypots) > 0 || len(potentialBaits) >= 2

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
			"honeypotCount":      len(honeypots),
			"potentialBaitCount": len(potentialBaits),
			"status":             "Honeypot accounts detected",
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
