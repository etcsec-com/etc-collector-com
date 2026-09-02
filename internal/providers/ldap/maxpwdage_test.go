package ldap

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFiletimeMaxPwdAgeToDays is the T_132/D5 regression test. It is
// deliberately a pure unit test on the sentinel value — established by
// security (docs/security-validation/results/t128-croise/METHODE-ET-VERDICTS.md,
// section A "Défaut adjacent") by reproducing the arithmetic outside the
// repo, not by confronting a live domain — because changing a shared lab's
// domain password policy to reach maxPwdAge's "never expires" sentinel was
// judged too intrusive.
func TestFiletimeMaxPwdAgeToDays(t *testing.T) {
	tests := []struct {
		name      string
		maxPwdAge int64
		want      int
	}{
		{"90 days", -77760000000000, 90},
		{"365 days", -315360000000000, 365},
		{"never-expires sentinel (0x8000000000000000)", math.MinInt64, maxPwdAgeNeverExpiresDays},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filetimeMaxPwdAgeToDays(tt.maxPwdAge)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestFiletimeMaxPwdAgeToDays_SentinelFailsComplianceThresholds confirms the
// fixed sentinel handling actually flips the two detectors that read it:
// both reject "> 90 days", so the day count must land above that instead of
// wrapping negative (which any threshold of the form "> N" treats as
// compliant).
func TestFiletimeMaxPwdAgeToDays_SentinelFailsComplianceThresholds(t *testing.T) {
	days := filetimeMaxPwdAgeToDays(math.MinInt64)
	assert.Greater(t, days, 90, "the 'never expires' sentinel must read as violating a '> 90 days' policy threshold, not silently comply")
}
