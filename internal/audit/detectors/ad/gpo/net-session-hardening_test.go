package gpo

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// The real NetCease/SrvsvcSessionInfo value is a REG_BINARY security
// descriptor; registrypol_parser.go's matching case only extracts REG_DWORD
// (.pol type 4) entries via getDWORDValue, so RegistrySettings.NetSessionHardening
// can currently never be populated by a genuinely hardened host - this
// detector fires unconditionally regardless of real configuration. This
// test fails against the old unqualified Description (implies a confirmed
// "not restricted" state) and passes once it discloses that the
// "configured" case cannot currently be confirmed.
func TestNetSessionHardening_DisclosesDetectionGap(t *testing.T) {
	data := &audit.DetectorData{}

	findings := NewNetSessionHardeningDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if findings[0].Count != 1 {
		t.Fatalf("Count = %d, want 1 (no registry setting available)", findings[0].Count)
	}
	if !strings.Contains(findings[0].Description, "could not be confirmed") {
		t.Fatalf("description should disclose that a hardened host cannot be positively confirmed, got %q", findings[0].Description)
	}
}
