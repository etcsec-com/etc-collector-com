package passwordpolicy

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	IDExpiration       = "PASSWORD_EXPIRATION_ENABLED"
	CategoryExpiration = audit.CategoryIdentity
)

// ExpirationDetector checks if password expiration is enabled
type ExpirationDetector struct {
	audit.BaseDetector
}

// NewPasswordExpirationEnabledDetector creates a new password expiration detector
func NewPasswordExpirationEnabledDetector() *ExpirationDetector {
	return &ExpirationDetector{
		BaseDetector: audit.NewBaseDetector(IDExpiration, CategoryExpiration),
	}
}

// Detect checks if password expiration is enabled
func (d *ExpirationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        IDExpiration,
		Severity:    types.SeverityMedium,
		Category:    string(CategoryExpiration),
		Title:       "Password Expiration Enabled",
		Description: "Password expiration is enabled. NIST 800-63B recommends against periodic password changes as they lead to weaker passwords.",
		Count:       0,
	}

	// Check for synced AD domain with password expiration
	if data.DomainInfo != nil && data.DomainInfo.MaxPasswordAge > 0 && data.DomainInfo.MaxPasswordAge < 365 {
		finding.Count = 1
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewPasswordExpirationEnabledDetector())
}
