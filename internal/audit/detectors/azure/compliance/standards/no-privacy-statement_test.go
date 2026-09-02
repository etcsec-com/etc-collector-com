package standards

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// B_075/T_069 — "couldn't probe" must be visible in the report, distinct from
// both a real finding and real silence: an Info-severity finding, not nil.
func TestNoPrivacyStatement_InfoFindingWhenNotProbed(t *testing.T) {
	d := NewNoPrivacyStatementDetector()
	data := &audit.DetectorData{}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (visible ignorance) when the endpoint was never probed, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Fatalf("expected Info severity for an unprobed check, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Title, "not determinable") {
		t.Fatalf("title must say the check wasn't determinable, got %q", findings[0].Title)
	}
}

func TestNoPrivacyStatement_SilentWhenConfigured(t *testing.T) {
	d := NewNoPrivacyStatementDetector()
	data := &audit.DetectorData{AzurePrivacyStatementProbed: true, AzurePrivacyStatementURL: "https://contoso.test/privacy"}

	if findings := d.Detect(context.Background(), data); len(findings) != 0 {
		t.Fatalf("expected no finding when a statement URL is configured, got %+v", findings)
	}
}

func TestNoPrivacyStatement_FiresWhenProbedAndEmpty(t *testing.T) {
	d := NewNoPrivacyStatementDetector()
	data := &audit.DetectorData{AzurePrivacyStatementProbed: true, AzurePrivacyStatementURL: ""}

	findings := d.Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when probed and genuinely unset, got %d", len(findings))
	}
}
