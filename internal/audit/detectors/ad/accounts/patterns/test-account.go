package patterns

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAccountDetector detects test accounts
type TestAccountDetector struct {
	audit.BaseDetector
}

// NewTestAccountDetector creates a new detector
func NewTestAccountDetector() *TestAccountDetector {
	return &TestAccountDetector{
		BaseDetector: audit.NewBaseDetector("TEST_ACCOUNT", audit.CategoryAccounts),
	}
}

var testPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^test`),
	regexp.MustCompile(`(?i)test$`),
	regexp.MustCompile(`(?i)_test`),
	regexp.MustCompile(`(?i)\.test`),
	regexp.MustCompile(`(?i)^demo`),
	regexp.MustCompile(`(?i)^temp`),
}

// Detect executes the detection
func (d *TestAccountDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		for _, pattern := range testPatterns {
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
		Title:       "Test Account",
		Description: "User accounts with test/demo/temp naming. Should be removed from production.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewTestAccountDetector())
}
