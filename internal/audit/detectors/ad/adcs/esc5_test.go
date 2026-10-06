package adcs

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	esc5DomainDN  = "DC=example,DC=com"
	esc5DomainSID = "S-1-5-21-9999999999-8888888888-7777777777"
	esc5Attacker  = esc5DomainSID + "-91234"
)

// TestESC5_CAComputerObjectInScope covers the ecart: SpecterOps's ESC5
// definition ("Vulnerable PKI Object Access Control") explicitly includes the
// CA server's own computer domain object alongside the PKI containers under
// CN=Public Key Services - a dangerous ACE on that computer object (e.g.
// GenericAll for an unprivileged principal, opening the door to RBCD/shadow
// credential takeover of the CA host) is just as much an ESC5 path as one on
// a PKI container. Before the fix, isPKIObject only matched DNs containing
// "public key services"/"enrollment services", so the CA's computer object -
// which lives under an OU, not under the PKI container - was never in scope
// no matter how permissive its ACL was.
func TestESC5_CAComputerObjectInScope(t *testing.T) {
	caComputerDN := "CN=CA01,OU=Servers," + esc5DomainDN

	data := &audit.DetectorData{
		IncludeDetails: true,
		DomainInfo:     &types.DomainInfo{DomainDN: esc5DomainDN, DomainSID: esc5DomainSID},
		CertAuthorities: []types.CertAuthority{
			{
				DN:          "CN=CorpCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + esc5DomainDN,
				Name:        "CorpCA",
				DNSHostName: "ca01.example.com",
			},
		},
		Computers: []types.Computer{
			{DN: caComputerDN, DNSHostName: "ca01.example.com"},
		},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: caComputerDN, Trustee: esc5Attacker, AccessMask: GenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewESC5Detector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("count = %d, want 1: a dangerous ACE on the CA's computer object should be in ESC5 scope", findings[0].Count)
	}
}

// TestESC5_BackupOperatorsExcludedOnPKIContainer covers the ecart: the
// previous exclusion list (isESC5AdminSID) only covered Domain/Enterprise/
// Schema Admins, built-in Administrators, SYSTEM and Account Operators.
// Backup Operators is a well-known BUILTIN privileged group; a default/
// expected grant to it on a PKI container was incorrectly reported as an
// ESC5 finding. The detector now reuses audit.IsPrivilegedSID, the same
// canonical exclusion list every other ACL detector in this codebase relies
// on, which also covers Server/Print/Backup Operators and Key Admins.
func TestESC5_BackupOperatorsExcludedOnPKIContainer(t *testing.T) {
	containerDN := "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + esc5DomainDN
	const backupOperators = "S-1-5-32-551" // BUILTIN\Backup Operators

	data := &audit.DetectorData{
		DomainInfo: &types.DomainInfo{DomainDN: esc5DomainDN, DomainSID: esc5DomainSID},
		ACLEntries: []types.ACLEntry{
			{ObjectDN: containerDN, Trustee: backupOperators, AccessMask: GenericAll, AceType: "ACCESS_ALLOWED"},
		},
	}

	findings := NewESC5Detector().Detect(context.Background(), data)
	if len(findings) != 1 || findings[0].Count != 0 {
		t.Fatalf("Backup Operators holding GenericAll on a PKI container should be excluded as a default privileged grant; got findings=%+v", findings)
	}
}
