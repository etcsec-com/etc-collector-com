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

var sharedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^shared`),
	regexp.MustCompile(`(?i)^common`),
	regexp.MustCompile(`(?i)^generic`),
	regexp.MustCompile(`(?i)^service`),
	regexp.MustCompile(`(?i)^svc`),
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
