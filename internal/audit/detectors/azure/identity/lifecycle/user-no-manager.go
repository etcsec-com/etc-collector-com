package lifecycle

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDNoManager       = "USER_NO_MANAGER"
	CategoryNoManager = audit.CategoryIdentity
)

// NoManagerDetector checks for users without a manager assigned
type NoManagerDetector struct {
	audit.BaseDetector
}

// NewUserNoManagerDetector creates a new no manager detector
func NewUserNoManagerDetector() *NoManagerDetector {
	return &NoManagerDetector{
		BaseDetector: audit.NewBaseDetector(IDNoManager, CategoryNoManager),
	}
}

// Detect finds user accounts without a manager attribute
func (d *NoManagerDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDNoManager,
		Severity:    types.SeverityLow,
		Category:    string(CategoryNoManager),
		Title:       "Users Without Manager Assigned",
		Description: "User accounts without a manager attribute. Manager data is needed for access reviews and organizational hierarchy.",
		Count:       0,
	}

	var affected []types.User

	for _, user := range data.Users {
		if user.Disabled {
			continue
		}

		if user.Manager == "" {
			affected = append(affected, user)
		}
	}

	finding.Count = len(affected)

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewUserNoManagerDetector())
}
