package kerberos

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestConstrainedDelegationOnDisabledAccount(t *testing.T) {
	userDN := "CN=svc,OU=Services,DC=test,DC=local"

	t.Run("disabled + Kerberos-only (attribute) branch fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, AllowedToDelegateTo: []string{"HOST/dc-01.test.local"}},
			},
			IncludeDetails: true,
		}
		findings := NewConstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("disabled account with the attribute branch must fire here, got %+v", findings)
		}
		if findings[0].Severity != types.SeverityLow {
			t.Fatalf("disabled half must be Low, got %s", findings[0].Severity)
		}
	})

	t.Run("disabled + protocol transition (bit) branch fires here", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc", Disabled: true, UserAccountControl: types.UACTrustedToAuthForDelegation},
			},
			IncludeDetails: true,
		}
		findings := NewConstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
		if len(findings) != 1 || findings[0].Count != 1 {
			t.Fatalf("disabled account with the bit branch must fire here, got %+v", findings)
		}
	})

	t.Run("active account does NOT fire here, either branch", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{
				{DN: userDN, SAMAccountName: "svc-bit", UserAccountControl: types.UACTrustedToAuthForDelegation},
				{DN: userDN, SAMAccountName: "svc-attr", AllowedToDelegateTo: []string{"HOST/dc-01.test.local"}},
			},
		}
		findings := NewConstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("active accounts must not be counted by the disabled-account detector, got count=%d", findings[0].Count)
		}
	})

	t.Run("disabled with neither signal does NOT fire", func(t *testing.T) {
		data := &audit.DetectorData{
			Users: []types.User{{DN: userDN, SAMAccountName: "svc", Disabled: true}},
		}
		findings := NewConstrainedDelegationOnDisabledAccountDetector().Detect(context.Background(), data)
		if findings[0].Count != 0 {
			t.Fatalf("a disabled account with neither signal must not fire, got count=%d", findings[0].Count)
		}
	})
}
