package password

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// CleartextStorageDetector detects accounts with cleartext password storage attributes
type CleartextStorageDetector struct {
	audit.BaseDetector
}

// NewCleartextStorageDetector creates a new detector
func NewCleartextStorageDetector() *CleartextStorageDetector {
	return &CleartextStorageDetector{
		BaseDetector: audit.NewBaseDetector("PASSWORD_CLEARTEXT_STORAGE", audit.CategoryPassword),
	}
}

// Detect executes the detection
func (d *CleartextStorageDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Check Unix password attributes (from LDAP)
		if u.UnixUserPassword || u.UserPassword {
			affected = append(affected, u)
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "Cleartext Password Storage",
		Description: "User accounts with attributes that may store passwords in cleartext or reversible format. These attributes (userPassword, unixUserPassword) can be read by attackers with LDAP access.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewCleartextStorageDetector())
}
