package other

import (
	"context"
	"regexp"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DescriptionSensitiveDetector checks for sensitive data in computer descriptions
type DescriptionSensitiveDetector struct {
	audit.BaseDetector
}

// NewDescriptionSensitiveDetector creates a new detector
func NewDescriptionSensitiveDetector() *DescriptionSensitiveDetector {
	return &DescriptionSensitiveDetector{
		BaseDetector: audit.NewBaseDetector("COMPUTER_DESCRIPTION_SENSITIVE", audit.CategoryComputers),
	}
}

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password|passwd|pwd`),
	regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), // IP addresses
	regexp.MustCompile(`(?i)admin|root|sa`),
}

// Detect executes the detection
func (d *DescriptionSensitiveDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.Computer

	for _, c := range data.Computers {
		if c.Description == "" {
			continue
		}
		for _, pattern := range sensitivePatterns {
			if pattern.MatchString(c.Description) {
				affected = append(affected, c)
				break
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Computer Description Sensitive",
		Description: "Computer description contains sensitive data (passwords, IPs, etc.). Information disclosure.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDescriptionSensitiveDetector())
}
