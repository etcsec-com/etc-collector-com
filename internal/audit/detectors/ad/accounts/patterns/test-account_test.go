package patterns

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestTestAccount_MatchesNamingPatterns is a coverage test, not a
// red/green regression test: this is a documented naming heuristic with
// no correctness defect (see the Detect doc comment). It pins the
// currently supported patterns.
func TestTestAccount_MatchesNamingPatterns(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"testuser", true},
		{"jdoe-test", true},
		{"demo-presenter", true},
		{"tempadmin", true},
		{"vuln-esc1-test", true}, // the lab's own plant/revert fixture naming
		{"jdupont", false},
	}

	for _, c := range cases {
		data := &audit.DetectorData{Users: []types.User{{SAMAccountName: c.name}}}
		findings := NewTestAccountDetector().Detect(context.Background(), data)
		got := findings[0].Count == 1
		if got != c.want {
			t.Errorf("%q: matched=%v, want %v", c.name, got, c.want)
		}
	}
}
