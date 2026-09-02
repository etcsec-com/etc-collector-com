package azure

import (
	"strings"
	"testing"
	"time"
)

func TestClassifyBackupError(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		mustHave string
	}{
		{"400 segment not found", "Graph API error 400: ...segment 'backup'...", "not yet generally available"},
		{"401 unauthorized", "Graph API error 401: ...", "authentication"},
		{"403 forbidden", "Graph API error 403: insufficient permissions", "BackupRestoreConfiguration.Read.All"},
		{"404 not configured", "Graph API error 404: not found", "not found on this tenant"},
		{"429 throttled", "Graph API error 429: throttled by Graph", "throttled"},
		{"network error", "dial tcp: lookup graph.microsoft.com: no such host", "probe failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyBackupError(tc.input)
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tc.mustHave)) {
				t.Errorf("classifyBackupError(%q):\n got:  %q\n want substring: %q", tc.input, got, tc.mustHave)
			}
		})
	}
}

func TestMakeBackupFallback_ShapeIsComplete(t *testing.T) {
	probedAt := time.Date(2026, 5, 6, 19, 0, 0, 0, time.UTC)
	got := makeBackupFallback("Graph API error 400: segment 'backup' not found", probedAt, "3.1.37")

	if got.Available {
		t.Error("Available should be false on fallback")
	}
	if got.Reason == "" {
		t.Error("Reason must be populated on fallback")
	}
	if got.Enabled {
		t.Error("Enabled should be false on fallback")
	}
	if got.RestorePoints == nil {
		t.Error("RestorePoints must be a non-nil empty slice (so JSON renders [] not null)")
	}
	if !got.ProbedAt.Equal(probedAt) {
		t.Errorf("ProbedAt = %v, want %v", got.ProbedAt, probedAt)
	}
	if got.CollectorVersion != "3.1.37" {
		t.Errorf("CollectorVersion = %q, want 3.1.37", got.CollectorVersion)
	}
	if got.EstimatedRecoveryTime == "" {
		t.Error("EstimatedRecoveryTime should carry an operator-readable message")
	}
}

func TestMakeBackupFallback_ReasonClassifiedByErrorCode(t *testing.T) {
	probedAt := time.Now().UTC()
	cases := []struct {
		name        string
		err         string
		mustContain string
	}{
		{"400 → API not yet GA", "Graph API error 400: ...", "not yet generally available"},
		{"401 → auth issue", "Graph API error 401: token rejected", "authentication"},
		{"403 → perm missing", "Graph API error 403: forbidden", "Read.All"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := makeBackupFallback(tc.err, probedAt, "3.1.37")
			if !strings.Contains(got.Reason, tc.mustContain) {
				t.Errorf("Reason = %q\n want substring: %q", got.Reason, tc.mustContain)
			}
		})
	}
}
