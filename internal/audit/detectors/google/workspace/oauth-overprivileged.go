package workspace

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// OAuthOverprivilegedDetector detects OAuth apps with excessive permissions
type OAuthOverprivilegedDetector struct {
	audit.BaseDetector
}

// NewOAuthOverprivilegedDetector creates a new detector
func NewOAuthOverprivilegedDetector() *OAuthOverprivilegedDetector {
	return &OAuthOverprivilegedDetector{
		BaseDetector: audit.NewBaseDetector("OAUTH_APP_OVERPRIVILEGED", audit.CategoryOAuth),
	}
}

// Detect checks for overprivileged OAuth applications
func (d *OAuthOverprivilegedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// TODO: Implement when Google provider is connected
	// Will query Admin SDK tokens API for third-party app access
	// Apps with broad scopes (Drive, Gmail, Admin) = finding

	return []types.Finding{{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Overprivileged OAuth Applications",
		Description: "Third-party OAuth apps with excessive permissions. Overprivileged apps can access sensitive data across the organization.",
		Count:       0,
	}}
}

func init() {
	audit.MustRegister(NewOAuthOverprivilegedDetector())
}
