package password

import (
	"context"
	"regexp"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CommonPatternsDetector detects accounts with names suggesting default/weak passwords
type CommonPatternsDetector struct {
	audit.BaseDetector
}

// NewCommonPatternsDetector creates a new detector
func NewCommonPatternsDetector() *CommonPatternsDetector {
	return &CommonPatternsDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_COMMON_PATTERNS", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *CommonPatternsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// Patterns that suggest default or weak passwords
	riskyNamePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)^admin$`),
		regexp.MustCompile(`(?i)^administrator$`),
		regexp.MustCompile(`(?i)^test$`),
		regexp.MustCompile(`(?i)^user$`),
		regexp.MustCompile(`(?i)^guest$`),
		regexp.MustCompile(`(?i)^temp$`),
		regexp.MustCompile(`(?i)^default$`),
		regexp.MustCompile(`(?i)^support$`),
		regexp.MustCompile(`(?i)^service$`),
		regexp.MustCompile(`(?i)^backup$`),
		regexp.MustCompile(`(?i)^demo$`),
		regexp.MustCompile(`(?i)password`),
		regexp.MustCompile(`123$`),
		regexp.MustCompile(`(?i)^sa$`),
		regexp.MustCompile(`(?i)^dba$`),
	}

	var affected []types.User
	var affectedNames []string

	for _, u := range data.Users {
		// Must be enabled
		if u.Disabled {
			continue
		}

		samName := strings.ToLower(u.SAMAccountName)
		for _, pattern := range riskyNamePatterns {
			if pattern.MatchString(samName) {
				affected = append(affected, u)
				if len(affectedNames) < 10 {
					affectedNames = append(affectedNames, u.SAMAccountName)
				}
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Common Password Pattern Risk",
		Description: "User accounts with names suggesting default or commonly-used passwords (admin, test, user, temp). These accounts are primary targets for password spraying attacks.",
		Count:       len(affected),
		Details: map[string]interface{}{
			"affectedAccountNames": affectedNames,
		},
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCommonPatternsDetector())
}
