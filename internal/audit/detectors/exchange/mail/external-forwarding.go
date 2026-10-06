package mail

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ExternalForwardingDetector detects mailboxes with external forwarding rules
type ExternalForwardingDetector struct {
	audit.BaseDetector
}

// NewExternalForwardingDetector creates a new detector
func NewExternalForwardingDetector() *ExternalForwardingDetector {
	return &ExternalForwardingDetector{
		BaseDetector: audit.NewBaseDetector("EXTERNAL_FORWARDING_ENABLED", audit.CategoryMailSecurity),
	}
}

// Detect checks for external mail forwarding
func (d *ExternalForwardingDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// TODO: Implement when Exchange provider is connected
	// Will query mailbox forwarding rules and transport rules
	// Mailboxes forwarding to external addresses = finding (data exfiltration risk)

	return []types.Finding{{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "External Mail Forwarding Enabled",
		Description: "Mailboxes with forwarding rules to external addresses. Auto-forwarding is a common data exfiltration technique.",
		Count:       0,
	}}
}

func init() {
	audit.MustRegister(NewExternalForwardingDetector())
}
