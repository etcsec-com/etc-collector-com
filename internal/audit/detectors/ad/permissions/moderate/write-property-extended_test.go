package moderate

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

const (
	wpeUserDN  = "CN=Akira Jackson,OU=IT,DC=example,DC=com"
	wpeTrustee = "S-1-5-21-1234567890-1111111111-2222222222-1108"

	wpeForceChangePasswordGUID = "00299570-246d-11d0-a768-00aa006e0529" // control-access right
	wpeScriptPathGUID          = "bf967a68-0de6-11d0-a285-00aa003049e2" // attribute

	wpeControlAccess = 0x00000100
	wpeWriteProperty = 0x00000020
)

func wpeData(aces ...types.ACLEntry) *audit.DetectorData {
	return &audit.DetectorData{
		IncludeDetails: true,
		ACLEntries:     aces,
		ObjectByDN: map[string]*audit.ObjectMeta{
			wpeUserDN: {DN: wpeUserDN, Name: "Akira Jackson", EntityType: types.EntityTypeUser},
		},
	}
}

func wpeDetect(t *testing.T, data *audit.DetectorData) types.Finding {
	t.Helper()
	findings := NewWritePropertyExtendedDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestWritePropertyExtended_ControlAccessVsWriteProperty(t *testing.T) {
	t.Run("User-Force-Change-Password with only WRITE_PROPERTY does NOT fire", func(t *testing.T) {
		// The GUID is a control-access right: WRITE_PROPERTY never grants it,
		// so this case was previously dead code that could never legitimately fire.
		f := wpeDetect(t, wpeData(
			types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeTrustee, ObjectType: wpeForceChangePasswordGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("WRITE_PROPERTY does not grant a control-access right, got count=%d", f.Count)
		}
	})

	t.Run("User-Force-Change-Password with CONTROL_ACCESS DOES fire", func(t *testing.T) {
		f := wpeDetect(t, wpeData(
			types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeTrustee, ObjectType: wpeForceChangePasswordGUID, AccessMask: wpeControlAccess, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("CONTROL_ACCESS is the correct right for this GUID, got count=%d", f.Count)
		}
	})

	t.Run("Script-Path with WRITE_PROPERTY still fires", func(t *testing.T) {
		f := wpeDetect(t, wpeData(
			types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeTrustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeWriteProperty, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 1 {
			t.Fatalf("Script-Path is an ordinary attribute, WRITE_PROPERTY must still fire, got count=%d", f.Count)
		}
	})

	t.Run("Script-Path with only CONTROL_ACCESS does NOT fire", func(t *testing.T) {
		f := wpeDetect(t, wpeData(
			types.ACLEntry{ObjectDN: wpeUserDN, Trustee: wpeTrustee, ObjectType: wpeScriptPathGUID, AccessMask: wpeControlAccess, AceType: "ACCESS_ALLOWED"},
		))
		if f.Count != 0 {
			t.Fatalf("CONTROL_ACCESS does not grant writing an ordinary attribute, got count=%d", f.Count)
		}
	})
}
