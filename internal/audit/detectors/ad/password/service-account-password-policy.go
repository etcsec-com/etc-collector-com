package password

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ServiceAccountPasswordPolicyDetector checks whether a Fine-Grained Password
// Policy with MinPasswordLength >= 20 applies to service accounts. PingCastle
// A-NoServicePolicy fires when no such policy exists.
type ServiceAccountPasswordPolicyDetector struct {
	audit.BaseDetector
}

func NewServiceAccountPasswordPolicyDetector() *ServiceAccountPasswordPolicyDetector {
	return &ServiceAccountPasswordPolicyDetector{
		BaseDetector: audit.NewBaseDetector("SERVICE_ACCOUNT_WEAK_PASSWORD_POLICY", audit.CategoryPassword),
	}
}

// isLikelyServiceAccount detects service accounts by SPN presence or naming
// conventions (svc-, sa-, sql*, iis*, service*).
func isLikelyServiceAccount(u types.User) bool {
	if len(u.ServicePrincipalNames) > 0 {
		return true
	}
	lower := strings.ToLower(u.SAMAccountName)
	for _, prefix := range []string{"svc_", "svc-", "sa_", "sa-", "sql", "iis", "app"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return strings.Contains(lower, "service")
}

func (d *ServiceAccountPasswordPolicyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Collect service account DNs (lowercased for comparison).
	svcDNs := make(map[string]bool)
	for i := range data.Users {
		if isLikelyServiceAccount(data.Users[i]) && data.Users[i].DN != "" {
			svcDNs[strings.ToLower(data.Users[i].DN)] = true
		}
	}

	// Check if any FGPP with MinPasswordLength >= 20 applies to at least one
	// service account (directly or via a group the svc is in).
	covered := false
	for _, fgpp := range data.FGPPs {
		if fgpp.MinPasswordLength < 20 {
			continue
		}
		for _, applyDN := range fgpp.AppliesTo {
			if svcDNs[strings.ToLower(applyDN)] {
				covered = true
				break
			}
			// Also check if the FGPP targets a group that contains a svc account.
			for i := range data.Groups {
				if strings.EqualFold(data.Groups[i].DN, applyDN) {
					for _, memberDN := range data.Groups[i].Members {
						if svcDNs[strings.ToLower(memberDN)] {
							covered = true
							break
						}
					}
				}
				if covered {
					break
				}
			}
			if covered {
				break
			}
		}
		if covered {
			break
		}
	}

	count := 0
	if len(svcDNs) > 0 && !covered {
		count = 1
	}

	finding := types.Finding{
		Type:     d.ID(),
		Severity: types.SeverityMedium,
		Category: string(d.Category()),
		Title:    "No Strong Password Policy for Service Accounts",
		Description: "No Fine-Grained Password Policy with MinimumPasswordLength >= 20 applies to " +
			"service accounts. Service accounts should have long, complex passwords since they " +
			"cannot use MFA and are primary targets for Kerberoasting.",
		Count: count,
		Details: map[string]interface{}{
			"serviceAccountCount": len(svcDNs),
			"recommendation":      "Create a FGPP with MinPasswordLength >= 20 and apply it to a group containing all service accounts.",
		},
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewServiceAccountPasswordPolicyDetector())
}
