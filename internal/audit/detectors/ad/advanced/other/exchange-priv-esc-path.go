package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ExchangePrivEscPathDetector detects Exchange privilege escalation paths.
//
// Source check corrected: the original description cited CVE-2019-1166
// ("Drop the MIC", an NTLM MIC-bypass tampering bug) as the reference for
// this finding. That CVE has nothing to do with Exchange. The actual
// technique this detector is about is PrivExchange (Dirk-jan Mollema,
// Jan 2019), mitigated by CVE-2019-0686 / ADV190007: by default the
// "Exchange Windows Permissions" group - not "Exchange Trusted Subsystem",
// which is merely a member of it - holds WriteDacl on the domain object,
// and Exchange's PushSubscription feature can be coerced into
// authenticating as the Exchange server's own machine account (a member of
// "Exchange Servers", nested in "Exchange Trusted Subsystem", nested in
// "Exchange Windows Permissions") to an attacker-controlled endpoint,
// enabling an NTLM relay that grants DCSync rights.
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
	var affectedUsers []types.User
	var affectedComputers []types.Computer

	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}
		for _, memberOf := range u.MemberOf {
			for _, eg := range exchangeGroups {
				if strings.Contains(strings.ToLower(memberOf), strings.ToLower(eg)) {
					affectedUsers = append(affectedUsers, u)
					break
				}
			}
		}
	}

	// "Exchange Servers" is, in a real Exchange deployment, populated with
	// the Exchange servers' own machine (computer) accounts - not user
	// accounts. A scan limited to data.Users never sees them, missing the
	// exact identity PrivExchange actually relays (the server's computer
	// account, coerced via PushSubscription).
	for _, c := range data.Computers {
		if c.Disabled {
			continue
		}
		for _, memberOf := range c.MemberOf {
			for _, eg := range exchangeGroups {
				if strings.Contains(strings.ToLower(memberOf), strings.ToLower(eg)) {
					affectedComputers = append(affectedComputers, c)
					break
				}
			}
		}
	}

	count := len(affectedUsers) + len(affectedComputers)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Exchange Privilege Escalation Risk",
		Description: "Accounts in Exchange security groups with potentially dangerous permissions. 'Exchange Windows Permissions' has WriteDacl on the domain object by default (PrivExchange, CVE-2019-0686 / ADV190007); 'Exchange Trusted Subsystem' is a member of that group, and 'Exchange Servers' (the Exchange servers' own machine accounts) is nested inside it.",
		Count:       count,
		Details: map[string]interface{}{
			"exchangeGroups": exchangeGroups,
			"recommendation": "Review Exchange group permissions on domain head. Apply PrivExchange mitigations.",
			"reference":      "CVE-2019-0686, ADV190007, PrivExchange",
		},
	}

	if data.IncludeDetails && count > 0 {
		entities := helpers.ToAffectedUserEntities(affectedUsers)
		entities = append(entities, helpers.ToAffectedComputerEntities(affectedComputers)...)
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewExchangePrivEscPathDetector())
}
