package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestDelegationUnknownTarget_ThreePartSPN covers a real Microsoft SPN format
// (serviceclass/host:port/servicename): extractHostFromSPN only stripped the
// port after the first "/", so a three-part SPN kept "/servicename" glued
// onto the host and was never recognized, even against a real, known
// computer. This case must be RED before the fix and green after it.
func TestDelegationUnknownTarget_ThreePartSPN(t *testing.T) {
	data := &audit.DetectorData{
		Computers: []types.Computer{
			{DN: "CN=SRV01,OU=Computers,DC=test,DC=local", SAMAccountName: "SRV01$", DNSHostName: "srv01.test.local"},
		},
		Users: []types.User{
			{DN: "CN=svc-3part,OU=Services,DC=test,DC=local", SAMAccountName: "svc-3part", AllowedToDelegateTo: []string{"ldap/srv01.test.local/test.local"}},
		},
		IncludeDetails: true,
	}
	findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("three-part SPN to a known computer must NOT be flagged unknown, got count=%d", findings[0].Count)
	}
}

// TestDelegationUnknownTarget covers extractHostFromSPN and the surrounding
// no-state-filter behavior with literal SPNs and hostnames, never built from
// the constants under test.
func TestDelegationUnknownTarget(t *testing.T) {
	knownComputers := []types.Computer{
		{DN: "CN=SRV01,OU=Computers,DC=test,DC=local", SAMAccountName: "SRV01$", DNSHostName: "srv01.test.local"},
		{DN: "CN=SRV02,OU=Computers,DC=test,DC=local", SAMAccountName: "SRV02$"},
	}

	t.Run("short hostname known via SAMAccountName fires as known (not unknown)", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: knownComputers,
			Users: []types.User{
				{DN: "CN=u1", SAMAccountName: "u1", AllowedToDelegateTo: []string{"cifs/srv02"}},
			},
			IncludeDetails: true,
		}
		findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Type != "DELEGATION_UNKNOWN_TARGET" {
			t.Fatalf("unexpected findings: %+v", findings)
		}
		if findings[0].Severity != types.SeverityHigh {
			t.Fatalf("expected severity high, got %s", findings[0].Severity)
		}
		if findings[0].Count != 0 {
			t.Fatalf("SPN host matching a computer SAMAccountName must not be unknown, got count=%d", findings[0].Count)
		}
	})

	t.Run("FQDN known via DNSHostName does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: knownComputers,
			Users: []types.User{
				{DN: "CN=u2", SAMAccountName: "u2", AllowedToDelegateTo: []string{"cifs/srv01.test.local"}},
			},
		}
		findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("SPN host matching a computer DNSHostName must not be unknown, got count=%d", findings[0].Count)
		}
	})

	t.Run("different case still matches (case-insensitive)", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: knownComputers,
			Users: []types.User{
				{DN: "CN=u3", SAMAccountName: "u3", AllowedToDelegateTo: []string{"cifs/SRV01.TEST.LOCAL"}},
			},
		}
		findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("case difference must not make a known host unknown, got count=%d", findings[0].Count)
		}
	})

	t.Run("host with port known does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: knownComputers,
			Users: []types.User{
				{DN: "CN=u4", SAMAccountName: "u4", AllowedToDelegateTo: []string{"mssqlsvc/srv01.test.local:1433"}},
			},
		}
		findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("port suffix must be stripped before the known-host lookup, got count=%d", findings[0].Count)
		}
	})

	t.Run("three-part SPN to a known computer does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: knownComputers,
			Users: []types.User{
				{DN: "CN=u5", SAMAccountName: "u5", AllowedToDelegateTo: []string{"ldap/srv01.test.local/test.local"}},
			},
		}
		findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("three-part SPN to a known host must not be unknown, got count=%d", findings[0].Count)
		}
	})

	t.Run("three-part SPN to an unknown computer DOES fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: knownComputers,
			Users: []types.User{
				{DN: "CN=u6", SAMAccountName: "u6", AllowedToDelegateTo: []string{"ldap/ghost.test.local/test.local"}},
			},
		}
		findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("three-part SPN to an unknown host must fire, got count=%d", findings[0].Count)
		}
	})

	t.Run("SPN without a slash is ignored", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: knownComputers,
			Users: []types.User{
				{DN: "CN=u7", SAMAccountName: "u7", AllowedToDelegateTo: []string{"noSlashHere"}},
			},
		}
		findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a SPN without any slash must be ignored (empty host), got count=%d", findings[0].Count)
		}
	})

	t.Run("empty host is ignored", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: knownComputers,
			Users: []types.User{
				{DN: "CN=u8", SAMAccountName: "u8", AllowedToDelegateTo: []string{"cifs/"}},
			},
		}
		findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("an empty host after the slash must be ignored, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled user counted (no state filter)", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: knownComputers,
			Users: []types.User{
				{DN: "CN=u9", SAMAccountName: "u9", Disabled: true, AllowedToDelegateTo: []string{"cifs/ghost.test.local"}},
			},
		}
		findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("a disabled user with an unknown SPN target must still be counted, got count=%d", findings[0].Count)
		}
	})

	t.Run("delegating computer counted", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: []types.Computer{
				knownComputers[0],
				knownComputers[1],
				{DN: "CN=SRV03,OU=Computers,DC=test,DC=local", SAMAccountName: "SRV03$", AllowedToDelegateTo: []string{"cifs/ghost.test.local"}},
			},
		}
		findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("a delegating computer with an unknown SPN target must be counted, got count=%d", findings[0].Count)
		}
	})

	t.Run("one known target and one unknown target on the same account counts once", func(t *testing.T) {
		data := &audit.DetectorData{
			Computers: knownComputers,
			Users: []types.User{
				{DN: "CN=u10", SAMAccountName: "u10", AllowedToDelegateTo: []string{"cifs/srv01.test.local", "cifs/ghost.test.local"}},
			},
		}
		findings := NewDelegationUnknownTargetDetector().Detect(context.Background(), data)
		if findings[0].Count != 1 {
			t.Fatalf("an account with one known and one unknown target must be counted once, not per-SPN, got count=%d", findings[0].Count)
		}
	})
}
