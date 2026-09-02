package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ExchangePrivEscPathDetector detects Exchange privilege escalation paths
type ExchangePrivEscPathDetector struct {
	audit.BaseDetector
}

// NewExchangePrivEscPathDetector creates a new detector
func NewExchangePrivEscPathDetector() *ExchangePrivEscPathDetector {
	return &ExchangePrivEscPathDetector{
		BaseDetector: audit.NewBaseDetector("EXCHANGE_PRIV_ESC_PATH", audit.CategoryAdvanced),
	}
}

// Exchange groups with dangerous permissions
var exchangeGroups = []string{
	"Exchange Trusted Subsystem",
	"Exchange Windows Permissions",
	"Organization Management",
	"Exchange Servers",
}

// Detect executes the detection
func (d *ExchangePrivEscPathDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		for _, memberOf := range u.MemberOf {
			for _, eg := range exchangeGroups {
				if strings.Contains(strings.ToLower(memberOf), strings.ToLower(eg)) {
					affected = append(affected, u)
					break
				}
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Exchange Privilege Escalation Risk",
		Description: "Users in Exchange security groups with potentially dangerous permissions. Exchange Trusted Subsystem has WriteDacl on domain by default (CVE-2019-1166).",
		Count:       len(affected),
		Details: map[string]interface{}{
			"exchangeGroups": exchangeGroups,
			"recommendation": "Review Exchange group permissions on domain head. Apply PrivExchange mitigations.",
			"reference":      "CVE-2019-1166, PrivExchange",
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewExchangePrivEscPathDetector())
}
