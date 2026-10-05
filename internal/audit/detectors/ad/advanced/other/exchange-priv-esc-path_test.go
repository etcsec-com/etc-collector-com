package other

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// In a real Exchange deployment, "Exchange Servers" is populated with the
// Exchange servers' own machine accounts, not user accounts - PrivExchange
// relays the server's computer-account authentication, not a human user's.
// A detector that only scans data.Users never sees this. This test fails
// against the old Users-only scan (Count=0, the computer is invisible) and
// passes once Computers are scanned too (Count=1).
func TestExchangePrivEscPath_DetectsComputerAccountInExchangeServers(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{
				DN:       "CN=MAIL01,OU=Exchange,DC=test,DC=local",
				MemberOf: []string{"CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=test,DC=local"},
			},
		},
	}

	findings := NewExchangePrivEscPathDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (Exchange server machine account should be caught)", findings[0].Count)
	}
}

// The description previously cited CVE-2019-1166 ("Drop the MIC", an NTLM
// bug unrelated to Exchange) as the reference for this Exchange-specific
// finding. Fails against the old text, passes once corrected to
// CVE-2019-0686 / ADV190007 (PrivExchange).
func TestExchangePrivEscPath_CitesCorrectCVE(t *testing.T) {
	data := &audit.DetectorData{}
	findings := NewExchangePrivEscPathDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	ref, _ := findings[0].Details["reference"].(string)
	if ref == "" || strings.Contains(ref, "CVE-2019-1166") {
		t.Fatalf("reference should not cite CVE-2019-1166, got %q", ref)
	}
	if !strings.Contains(ref, "CVE-2019-0686") {
		t.Fatalf("reference should cite CVE-2019-0686 (PrivExchange), got %q", ref)
	}
}
