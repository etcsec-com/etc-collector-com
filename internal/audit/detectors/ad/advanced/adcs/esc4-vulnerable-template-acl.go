package adcs

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ESC4VulnerableTemplateACLDetector detects ESC4 vulnerable template ACLs
type ESC4VulnerableTemplateACLDetector struct {
	audit.BaseDetector
}

// NewESC4VulnerableTemplateACLDetector creates a new detector
func NewESC4VulnerableTemplateACLDetector() *ESC4VulnerableTemplateACLDetector {
	return &ESC4VulnerableTemplateACLDetector{
		BaseDetector: audit.NewBaseDetector("ESC4_VULNERABLE_TEMPLATE_ACL", audit.CategoryAdvanced),
	}
}

// Detect executes the detection
func (d *ESC4VulnerableTemplateACLDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affectedNames []string

	for _, t := range data.CertTemplates {
		// Vulnerable if: has weak ACL allowing modification
		if t.HasWeakACL {
			name := t.Name
			if name == "" {
				name = t.DisplayName
			}
			affectedNames = append(affectedNames, name)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ESC4 Vulnerable Template ACL",
		Description: "Certificate template with weak ACLs. Can modify template to make it vulnerable to ESC1/ESC2.",
		Count:       len(affectedNames),
	}

	if data.IncludeDetails && len(affectedNames) > 0 {
		entities := make([]types.AffectedEntity, len(affectedNames))
		for i, name := range affectedNames {
			entities[i] = types.AffectedEntity{
				Type:           "certTemplate",
				SAMAccountName: name,
			}
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

// init() commented out - duplicate of adcs/esc4.go
// func init() {
// 	audit.MustRegister(NewESC4VulnerableTemplateACLDetector())
// }
