package password

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// InDescriptionDetector detects accounts with passwords in the description field
type InDescriptionDetector struct {
	audit.BaseDetector
}

// NewInDescriptionDetector creates a new detector
func NewInDescriptionDetector() *InDescriptionDetector {
	return &InDescriptionDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_IN_DESCRIPTION", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *InDescriptionDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User
	// matchedPatterns[i] holds the pattern names for affected[i] — the report
	// says WHICH kind of credential was found, never the text that matched.
	var matchedPatterns [][]string

	for _, u := range data.Users {
		// The pattern table lives in pkg/types alongside the entity mappers so
		// that what this detector flags is exactly what the mappers redact
		// (T_031). Matching behaviour is unchanged.
		if names := types.MatchSecretPatterns(u.Description); len(names) > 0 {
			affected = append(affected, u)
			matchedPatterns = append(matchedPatterns, names)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Password in Description",
		Description: "User accounts with passwords or password-like strings in the description field. Cleartext credential exposure.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		entities := helpers.ToAffectedUserEntities(affected)
		// This finding exists BECAUSE the description holds a credential, so it
		// ships none of it — not even the redacted remainder, which would still
		// point at the secret's position. The entity carries the account plus
		// the name of the pattern that matched, which is what an administrator
		// needs to find and clear the value on the DC.
		//
		// Same contract as scanForCPassword (smb/client.go:264-304): prove the
		// exposure, name its shape, never carry the value.
		for i := range entities {
			entities[i].Description = "matched credential pattern: " + strings.Join(matchedPatterns[i], ", ")
		}
		finding.AffectedEntities = entities
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewInDescriptionDetector())
}
