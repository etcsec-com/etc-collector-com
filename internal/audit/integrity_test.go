package audit

import (
	"testing"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// TestIntegrityHashIsDeterministic ensures the same input produces the
// same hash across calls. If this ever fails, the canonical form has
// drifted (probably a non-deterministic field — map with random iteration,
// pointer comparison) and the integrity scheme is broken.
func TestIntegrityHashIsDeterministic(t *testing.T) {
	report := &types.AuditResponse{
		Success:  true,
		Provider: "ad",
		Audit: &types.AuditReport{
			Summary: &types.SummarySection{
				ComplianceScores: []types.FrameworkScore{
					{Framework: "ANSSI_PA099", Score: 91.5, Rating: "low"},
				},
			},
		},
	}
	h1, err := IntegrityHash(report)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	h2, err := IntegrityHash(report)
	if err != nil {
		t.Fatalf("hash 2: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s vs %s", h1, h2)
	}
}

// TestIntegrityRoundtripVerify computes the signature, attaches it, then
// calls VerifyIntegrity. Must succeed.
func TestIntegrityRoundtripVerify(t *testing.T) {
	report := &types.AuditResponse{Success: true, Provider: "ad"}
	sig, err := ComputeIntegrity(report)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	report.Integrity = sig
	if err := VerifyIntegrity(report); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestIntegrityDetectsTampering modifies a field after signing — verify
// must fail (this is the whole point of the feature).
func TestIntegrityDetectsTampering(t *testing.T) {
	report := &types.AuditResponse{Success: true, Provider: "ad"}
	sig, _ := ComputeIntegrity(report)
	report.Integrity = sig

	// Tamper.
	report.Provider = "ad-tampered"

	if err := VerifyIntegrity(report); err == nil {
		t.Fatalf("verify should have failed after tampering")
	}
}

// TestIntegrityRejectsMissingField ensures a report without integrity
// signature is reported clearly.
func TestIntegrityRejectsMissingField(t *testing.T) {
	report := &types.AuditResponse{Success: true, Provider: "ad"}
	if err := VerifyIntegrity(report); err == nil {
		t.Fatalf("verify should error when Integrity is nil")
	}
}
