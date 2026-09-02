package rodc

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func run(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	d := NewRODCPrivilegedCachingDetector()
	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestRODC_NoRODCs(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "DC01$", IsRODC: false, RevealedList: []string{"CN=Administrator,DC=test,DC=local"}},
		},
		Users: []types.User{
			{DN: "CN=Administrator,DC=test,DC=local", AdminCount: true},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 0 {
		t.Fatalf("expected 0 findings for domain with no RODCs, got %d", f.Count)
	}
}

func TestRODC_EmptyRevealedList(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true, RevealedList: nil},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 0 {
		t.Fatalf("expected 0 findings for RODC with empty revealed list, got %d", f.Count)
	}
}

func TestRODC_NonPrivilegedCached(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true,
				RevealedList: []string{"CN=JohnDoe,OU=Users,DC=test,DC=local"}},
		},
		Users: []types.User{
			{DN: "CN=JohnDoe,OU=Users,DC=test,DC=local", SAMAccountName: "jdoe", AdminCount: false},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 0 {
		t.Fatalf("expected 0 findings for non-privileged reveal, got %d", f.Count)
	}
}

func TestRODC_PrivilegedCached(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true,
				RevealedList: []string{"CN=Administrator,DC=test,DC=local"}},
		},
		Users: []types.User{
			{DN: "CN=Administrator,DC=test,DC=local", SAMAccountName: "Administrator", AdminCount: true},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 1 {
		t.Fatalf("expected 1 finding for privileged reveal, got %d", f.Count)
	}
	if f.Severity != types.SeverityCritical {
		t.Fatalf("expected severity critical, got %s", f.Severity)
	}
}

func TestRODC_MultipleRODCsMixed(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{SAMAccountName: "RODC01$", DNSHostName: "rodc01.test.local", IsRODC: true,
				RevealedList: []string{"CN=Administrator,DC=test,DC=local"}},
			{SAMAccountName: "RODC02$", DNSHostName: "rodc02.test.local", IsRODC: true,
				RevealedList: []string{"CN=JohnDoe,OU=Users,DC=test,DC=local"}},
			{SAMAccountName: "RODC03$", DNSHostName: "rodc03.test.local", IsRODC: true,
				RevealedList: []string{"CN=DomainAdminsGroup,DC=test,DC=local"}},
		},
		Users: []types.User{
			{DN: "CN=Administrator,DC=test,DC=local", SAMAccountName: "Administrator", AdminCount: true},
			{DN: "CN=JohnDoe,OU=Users,DC=test,DC=local", SAMAccountName: "jdoe", AdminCount: false},
		},
		Groups: []types.Group{
			{DN: "CN=DomainAdminsGroup,DC=test,DC=local", SAMAccountName: "Domain Admins", ObjectSID: "S-1-5-21-1-2-3-512"},
		},
		IncludeDetails: true,
	}
	f := run(t, data)
	if f.Count != 2 {
		t.Fatalf("expected 2 findings (RODC01 + RODC03), got %d", f.Count)
	}
}
