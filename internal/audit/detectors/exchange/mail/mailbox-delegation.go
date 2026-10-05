package mail

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// MailboxDelegationDetector detects excessive mailbox delegations
type MailboxDelegationDetector struct {
	audit.BaseDetector
}

// NewMailboxDelegationDetector creates a new detector
func NewMailboxDelegationDetector() *MailboxDelegationDetector {
	return &MailboxDelegationDetector{
		BaseDetector: audit.NewBaseDetector("EXCESSIVE_MAILBOX_DELEGATION", audit.CategoryMailSecurity),
	}
}

// Detect checks for excessive mailbox delegations
func (d *MailboxDelegationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// TODO: Implement when Exchange provider is connected
	// Will query mailbox permissions (FullAccess, SendAs, SendOnBehalf)
	// Users with access to many mailboxes or unexpected delegations = finding

	return []types.Finding{{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Excessive Mailbox Delegation",
		Description: "Mailboxes with broad delegation permissions. Excessive delegations may indicate privilege creep or misconfiguration.",
		Count:       0,
	}}
}

func init() {
	audit.MustRegister(NewMailboxDelegationDetector())
}
