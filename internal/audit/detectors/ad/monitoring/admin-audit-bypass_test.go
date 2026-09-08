package monitoring

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestAdminAuditBypass_DescribesCredentialTheftNotAuditBypass locks in the
// fix for the mislabeled claim that Protected Users membership is an audit
// control: it protects against credential theft (NTLM, weak Kerberos, cached
// credentials), it does not enable or disable auditing.
func TestAdminAuditBypass_DescribesCredentialTheftNotAuditBypass(t *testing.T) {
	d := NewAdminAuditBypassDetector()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)

	t.Run("title and description no longer claim an audit-bypass capability", func(t *testing.T) {
		data := &audit.DetectorData{Now: now}
		findings := d.Detect(context.Background(), data)
		title := strings.ToLower(findings[0].Title)
		desc := strings.ToLower(findings[0].Description)
		if strings.Contains(title, "bypass audit") || strings.Contains(desc, "bypass audit controls") {
			t.Fatalf("finding still claims audit-bypass: title=%q description=%q", findings[0].Title, findings[0].Description)
		}
		if !strings.Contains(desc, "credential") {
			t.Fatalf("expected description to describe credential-theft exposure, got %q", findings[0].Description)
		}
	})

	t.Run("privileged account outside Protected Users with a stale password: flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{SAMAccountName: "admin1", AdminCount: true, PasswordLastSet: now.AddDate(-1, 0, 0)},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("expected count=1, got %d", findings[0].Count)
		}
	})

	t.Run("privileged account in Protected Users: not flagged", func(t *testing.T) {
		data := &audit.DetectorData{
			Now: now,
			Users: []types.User{
				{
					SAMAccountName:  "admin2",
					AdminCount:      true,
					PasswordLastSet: now.AddDate(-1, 0, 0),
					MemberOf:        []string{"CN=Protected Users,CN=Users,DC=example,DC=com"},
				},
			},
		}
		findings := d.Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("expected count=0 (protected), got %d", findings[0].Count)
		}
	})
}
