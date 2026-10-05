package patterns

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SharedAccountDetector detects shared accounts
type SharedAccountDetector struct {
	audit.BaseDetector
}

// NewSharedAccountDetector creates a new detector
func NewSharedAccountDetector() *SharedAccountDetector {
	return &SharedAccountDetector{
		BaseDetector: audit.NewBaseDetector("SHARED_ACCOUNT", audit.CategoryAccounts),
	}
}

// sharedPatterns intentionally excludes "^service"/"^svc": those prefixes
// are already claimed by the SERVICE_ACCOUNT_* detectors
// (accounts/service-accounts/naming.go, utils.go's isServiceAccount, used
// by old-password.go/privileged.go/interactive.go). Keeping them here
// double-counted the same accounts under two detector IDs and mislabeled
// them "shared" when ~13/17 real lab instances were actually service
// accounts (svc-/service-prefixed), not human-shared accounts. No official
// source prescribes exact shared-account naming regexes - CIS Controls v8
// Control 5 (Account Management) discusses the RISK of shared/generic
// accounts in general terms (ban or track with a formal exception) but
// gives no naming convention - so this pattern list remains a product
// heuristic; the fix here is eliminating the cross-detector overlap, not
// inventing a sourced pattern set.
var sharedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^shared`),
	regexp.MustCompile(`(?i)^common`),
	regexp.MustCompile(`(?i)^generic`),
	regexp.MustCompile(`(?i)^guest-`),
}

// Detect executes the detection
func (d *SharedAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		for _, pattern := range sharedPatterns {
			if pattern.MatchString(u.SAMAccountName) {
				affected = append(affected, u)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Shared Account",
		Description: "User accounts with shared/generic naming. Prevents proper accountability.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSharedAccountDetector())
}
