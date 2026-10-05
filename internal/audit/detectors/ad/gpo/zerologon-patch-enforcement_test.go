package gpo

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestZerologon_HonestlyRescoped covers an ecart: the old finding was
// Severity Critical, titled "Zerologon (CVE-2020-1472) Enforcement Not
// Enabled", and its Description claimed that without
// FullSecureChannelProtection=1 "Domain Controllers may still accept
// unauthenticated Netlogon connections, allowing complete domain takeover"
// - as if this registry value directly indicates live Zerologon exposure.
// Per Microsoft KB4557222, since the February 9, 2021 Enforcement Phase
// every patched DC enforces the Netlogon secure channel protection
// unconditionally regardless of this key, and Microsoft states the key "is
// no longer needed and will no longer be supported". So on any DC patched
// since Feb 2021 (virtually all of them, in any audit run today), this
// value is inert and tells you nothing about actual vulnerability. This
// test fails against the old Critical severity / domain-takeover framing
// and passes once the finding is honestly scoped to a low-severity legacy
// registry hygiene check.
func TestZerologon_HonestlyRescoped(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID}": {RegistrySettings: &audit.RegistrySettings{}}, // ZerologonEnforcement unset
		},
	}

	findings := NewZerologonDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]

	if f.Count != 1 {
		t.Fatalf("expected Count=1 (unset FullSecureChannelProtection still flagged), got %d", f.Count)
	}
	if f.Severity == types.SeverityCritical {
		t.Fatalf("severity must no longer be Critical - this value cannot indicate live Zerologon exposure on a patched DC, got %q", f.Severity)
	}
	if strings.Contains(f.Description, "allowing complete domain takeover") {
		t.Fatalf("description must not claim this indicates domain takeover risk, got %q", f.Description)
	}
	if !strings.Contains(f.Description, "does NOT measure actual DC patch level") && !strings.Contains(f.Description, "no longer needed") {
		t.Fatalf("description should honestly disclose that this is a legacy/inert signal post-February-2021, got %q", f.Description)
	}
}

// TestZerologon_StillFiresWhenExplicitlyDisabled is an unchanged-behavior
// regression pin: the underlying signal (was the registry value explicitly
// set to 1) is preserved, only its framing changed.
func TestZerologon_StillFiresWhenExplicitlyDisabled(t *testing.T) {
	v := 1
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID}": {RegistrySettings: &audit.RegistrySettings{ZerologonEnforcement: &v}},
		},
	}
	findings := NewZerologonDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 0 {
		t.Fatalf("Count = %d, want 0 (FullSecureChannelProtection=1 configured)", findings[0].Count)
	}
}
