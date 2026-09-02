package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// integrityAlgorithm is the algorithm string written into the report and
// verified by `audit verify`. Bumped when the canonical form changes.
const integrityAlgorithm = "sha256-canonical-json"

// integritySpec is the human-readable recipe an auditor follows to recompute
// the hash without using the etc-collector binary. The spec is embedded in
// the report so it travels with the data.
const integritySpec = "Hash = sha256(json.Marshal(report)) with the report's `integrity` field set to null. " +
	"Verify with: `etc-collector audit verify <file.json>` or programmatically with the IntegrityHash function in github.com/etcsec-com/etc-collector/internal/audit."

// ComputeIntegrity returns the IntegritySignature for the given AuditResponse.
// Side-effect free — does NOT modify report. The audit CLI calls this just
// before serialization and assigns the result to report.Integrity.
//
// v3.1.19 — added so an ANSSI auditor can detect post-audit modifications
// of the JSON report. No secret involved (proves integrity, not provenance).
func ComputeIntegrity(report *types.AuditResponse) (*types.IntegritySignature, error) {
	hash, err := IntegrityHash(report)
	if err != nil {
		return nil, err
	}
	return &types.IntegritySignature{
		Algorithm:  integrityAlgorithm,
		Hash:       hash,
		ComputedAt: time.Now().UTC(),
		Spec:       integritySpec,
	}, nil
}

// IntegrityHash computes the SHA-256 of the canonical JSON form of report.
// Canonical = standard Go encoding/json output with report.Integrity set to
// nil. Go's encoding/json sorts map keys alphabetically (since Go 1.12) and
// serializes struct fields in declaration order, which is deterministic
// across runs and across machines.
func IntegrityHash(report *types.AuditResponse) (string, error) {
	saved := report.Integrity
	report.Integrity = nil
	defer func() { report.Integrity = saved }()

	canonical, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("marshal report: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyIntegrity recomputes the integrity hash on `report` and compares it
// to report.Integrity.Hash. Returns nil on match, an error explaining the
// mismatch otherwise. If the report has no Integrity field, returns an error.
func VerifyIntegrity(report *types.AuditResponse) error {
	if report.Integrity == nil {
		return fmt.Errorf("report has no integrity field — was it produced by a pre-v3.1.19 collector?")
	}
	if report.Integrity.Algorithm != integrityAlgorithm {
		return fmt.Errorf("unsupported integrity algorithm %q (expected %q)", report.Integrity.Algorithm, integrityAlgorithm)
	}
	want := report.Integrity.Hash
	got, err := IntegrityHash(report)
	if err != nil {
		return fmt.Errorf("recompute hash: %w", err)
	}
	if want != got {
		return fmt.Errorf("integrity MISMATCH: stored=%s recomputed=%s", want, got)
	}
	return nil
}
