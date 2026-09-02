package audit

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

func TestSIDToEntity_WellKnown(t *testing.T) {
	cases := []struct {
		sid       string
		wantName  string
		wantScope string
	}{
		{"S-1-1-0", "Everyone", "WellKnown"},
		{"S-1-5-11", "Authenticated Users", "WellKnown"},
		{"S-1-5-18", "Local System", "WellKnown"},
		{"S-1-5-32-544", "Administrators", "BuiltinDomain"},
		{"S-1-5-32-549", "Server Operators", "BuiltinDomain"},
		{"S-1-5-32-580", "Remote Management Users", "BuiltinDomain"},
	}
	for _, tc := range cases {
		t.Run(tc.sid, func(t *testing.T) {
			got := SIDToEntity(tc.sid)
			if got.Type != types.EntityTypeWellKnownSid {
				t.Errorf("Type = %q, want wellKnownSid", got.Type)
			}
			if got.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tc.wantName)
			}
			if got.Scope != tc.wantScope {
				t.Errorf("Scope = %q, want %q", got.Scope, tc.wantScope)
			}
			if got.SID != tc.sid {
				t.Errorf("SID = %q, want %q", got.SID, tc.sid)
			}
			if got.Unresolved {
				t.Errorf("Unresolved = true, want false for well-known SID")
			}
		})
	}
}

func TestSIDToEntity_Unknown(t *testing.T) {
	// Domain-specific SID like Domain Admins — RID changes per domain so it
	// must NOT be in the static lookup. Falls back to unresolved principal.
	sid := "S-1-5-21-1234567890-1111111111-2222222222-512"
	got := SIDToEntity(sid)
	if got.Type != types.EntityTypePrincipal {
		t.Errorf("Type = %q, want principal", got.Type)
	}
	if got.SID != sid {
		t.Errorf("SID = %q, want %q", got.SID, sid)
	}
	if !got.Unresolved {
		t.Errorf("Unresolved = false, want true for non-well-known SID")
	}
	if got.Name != "" {
		t.Errorf("Name = %q, want empty for unresolved", got.Name)
	}
}

func TestWellKnownSIDsCoverage(t *testing.T) {
	// Spec requires 37 entries. Guard against accidental deletion.
	if len(wellKnownSIDs) < 37 {
		t.Errorf("wellKnownSIDs has %d entries, spec requires at least 37", len(wellKnownSIDs))
	}
}

// T_024 — the trustee filter the ACL detectors rely on. T_023 showed how this
// goes wrong: matching the substring "s-1-5-21-" excluded every domain
// principal, i.e. exactly the population the detectors exist to catch. These
// cases pin both ends.
func TestIsBuiltinAdminTrustee(t *testing.T) {
	const domain = "S-1-5-21-1234567890-1111111111-2222222222"

	cases := []struct {
		sid  string
		want bool
		why  string
	}{
		// Expected holders of dangerous rights on every object — filtered out.
		{"S-1-5-18", true, "LOCAL SYSTEM"},
		{"S-1-5-10", true, "SELF"},
		{"S-1-5-9", true, "ENTERPRISE DOMAIN CONTROLLERS"},
		{"S-1-3-0", true, "CREATOR OWNER"},
		{"S-1-5-32-544", true, "BUILTIN\\Administrators"},
		{"S-1-5-32-548", true, "BUILTIN\\Account Operators"},
		{domain + "-512", true, "Domain Admins"},
		{domain + "-519", true, "Enterprise Admins"},
		{domain + "-518", true, "Schema Admins"},

		// The population the detectors MUST keep reporting.
		{domain + "-1337", false, "ordinary domain group"},
		{domain + "-93801", false, "the unresolvable SID holding full control on 293 accounts"},
		{domain + "-1105", false, "ordinary domain user"},
		{"S-1-1-0", false, "Everyone is not an admin principal"},
		{"S-1-5-11", false, "Authenticated Users is not an admin principal"},
		{"S-1-5-32-554", false, "Pre-Windows 2000 Compatible Access is not an admin principal"},

		// The suffix match must respect the RID boundary.
		{domain + "-1512", false, "-1512 must not match the -512 suffix"},
		{"", false, "empty trustee"},
	}

	for _, tc := range cases {
		if got := IsBuiltinAdminTrustee(tc.sid); got != tc.want {
			t.Errorf("IsBuiltinAdminTrustee(%q) = %v, want %v — %s", tc.sid, got, tc.want, tc.why)
		}
	}
}

// TestIsGrantACE pins DET_10: AceType carries the Windows-style values produced
// by acl_parser.go's aceTypeToString, never the literal "deny" that the old
// DCSYNC_CAPABLE guard compared against.
func TestIsGrantACE(t *testing.T) {
	cases := []struct {
		aceType string
		want    bool
	}{
		{"ACCESS_ALLOWED", true},
		{"ACCESS_ALLOWED_OBJECT", true},
		{"ACCESS_DENIED", false},
		{"ACCESS_DENIED_OBJECT", false},
		{"SYSTEM_AUDIT", false},
		{"SYSTEM_AUDIT_OBJECT", false},
		{"UNKNOWN_9", false}, // fail closed on an ACE we cannot classify
		{"", false},
		{"deny", false}, // the literal the dead guard tested for
	}
	for _, tc := range cases {
		if got := IsGrantACE(tc.aceType); got != tc.want {
			t.Errorf("IsGrantACE(%q) = %v, want %v", tc.aceType, got, tc.want)
		}
	}
}
