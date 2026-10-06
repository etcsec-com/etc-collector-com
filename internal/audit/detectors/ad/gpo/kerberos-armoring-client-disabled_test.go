package gpo

import (
	"context"
	"strings"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// The registry value this detector reads (RequireFAST, under a
// Kerberos\Parameters key - see registrypol_parser.go) belongs to the
// "Fail authentication requests when Kerberos armoring is not available"
// GPO, not "Kerberos client support for claims, compound authentication and
// Kerberos armoring" (a separate policy that writes a different value).
// This test fails against the old recommendation text (names the wrong
// policy) and passes once it names the policy that actually corresponds to
// RequireFAST.
func TestKerberosArmoringClient_RecommendsCorrectGPO(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"GUID": {RegistrySettings: &audit.RegistrySettings{}},
		},
	}

	findings := NewKerberosArmoringClientDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	rec, _ := findings[0].Details["recommendation"].(string)
	if strings.Contains(rec, "client support for claims") {
		t.Fatalf("recommendation should not name the claims/compound-auth policy, got %q", rec)
	}
	if !strings.Contains(rec, "Fail authentication requests when Kerberos armoring is not available") {
		t.Fatalf("recommendation should name the policy that writes RequireFAST, got %q", rec)
	}
}
