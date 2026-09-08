package security

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// A prior version of this detector claimed to have detected SMBv1 and NTLMv1 via a
// static `"protocols": []string{"SMBv1","NTLMv1","DES","RC4"}` list, when
// it never observes either protocol. This pins that the misleading
// attribution is gone and Details instead reports which of the two signals
// actually measured (legacy OS, weak Kerberos encryption) fired.
func TestLegacyProtocol_NoFalseProtocolClaim(t *testing.T) {
	c := types.Computer{
		DN:              "CN=OLDBOX,DC=example,DC=com",
		OperatingSystem: "Windows Server 2003",
	}
	data := &audit.DetectorData{IncludeDetails: true, Computers: []types.Computer{c}}

	findings := NewLegacyProtocolDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Count != 1 {
		t.Fatalf("Count = %d, want 1", f.Count)
	}
	if _, present := f.Details["protocols"]; present {
		t.Fatalf("Details still carries a static \"protocols\" list implying SMBv1/NTLMv1 were observed - they are not measured by this detector")
	}
	if got := f.Details["legacyOSCount"]; got != 1 {
		t.Fatalf("Details[legacyOSCount] = %v, want 1", got)
	}
	if got := f.Details["weakKerberosEncryption"]; got != 0 {
		t.Fatalf("Details[weakKerberosEncryption] = %v, want 0", got)
	}
}
