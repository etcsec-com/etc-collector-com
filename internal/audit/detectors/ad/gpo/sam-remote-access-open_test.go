package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestRemoteSAM_ParsesDACLInsteadOfSubstringMatch covers an ecart: the
// detector used to accept ANY SDDL string containing the two characters
// "D:" as proof that remote SAM access was restricted
// (strings.Contains(sddl, "D:")). Since "D:" is just the DACL marker present
// in nearly every syntactically valid SDDL string, a GPO explicitly granting
// remote SAM access to Everyone (WD) - a permissive misconfiguration, not a
// restriction - still contained "D:" and was silently cleared. This test
// fails against that substring check (Count=0 for the Everyone-grant case)
// and passes once the DACL is actually parsed for who the Allow ACEs name.
func TestRemoteSAM_ParsesDACLInsteadOfSubstringMatch(t *testing.T) {
	cases := []struct {
		name      string
		sddl      *string
		wantCount int
	}{
		{"not configured (nil)", nil, 1},
		{"empty string - not enforced per Microsoft", strPtr(""), 1},
		{"Microsoft's hardened default: RC to BA only", strPtr("O:SYG:SYD:(A;;RC;;;BA)"), 0},
		{"RC restricted to Domain Admins only", strPtr("O:SYG:SYD:(A;;RC;;;DA)"), 0},
		{
			name:      "RC granted to Everyone (WD) - contains D: but IS open",
			sddl:      strPtr("O:BAG:BAD:(A;;RC;;;WD)"),
			wantCount: 1,
		},
		{
			name:      "RC granted to Authenticated Users (AU) - contains D: but IS open",
			sddl:      strPtr("O:BAG:BAD:(A;;RC;;;AU)"),
			wantCount: 1,
		},
		{
			name:      "Deny to Everyone + Allow to BA - actually restricted",
			sddl:      strPtr("O:SYG:SYD:(D;;RC;;;WD)(A;;RC;;;BA)"),
			wantCount: 0,
		},
		{
			name:      "malformed: has D: prefix but no parseable ACE",
			sddl:      strPtr("D:"),
			wantCount: 1,
		},
		{
			name:      "hex access mask form granting READ_CONTROL to Everyone",
			sddl:      strPtr("O:BAG:BAD:(A;;0x20000;;;WD)"),
			wantCount: 1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := &audit.DetectorData{
				GPOPolicies: map[string]*audit.GPOPolicy{
					"{6AC1786C-016F-11D2-945F-00C04FB984F9}": {
						RegistrySettings: &audit.RegistrySettings{RestrictRemoteSAM: c.sddl},
					},
				},
			}
			findings := NewRemoteSAMDetector().Detect(context.Background(), data)
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding, got %d", len(findings))
			}
			if findings[0].Count != c.wantCount {
				sddl := "<nil>"
				if c.sddl != nil {
					sddl = *c.sddl
				}
				t.Fatalf("Count = %d, want %d (sddl=%q)", findings[0].Count, c.wantCount, sddl)
			}
		})
	}
}

func strPtr(s string) *string { return &s }
