package laps

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LapsPasswordLeakedDetector detects LAPS passwords with excessive readers
type LapsPasswordLeakedDetector struct {
	audit.BaseDetector
}

// NewLapsPasswordLeakedDetector creates a new detector
func NewLapsPasswordLeakedDetector() *LapsPasswordLeakedDetector {
	return &LapsPasswordLeakedDetector{
		BaseDetector: audit.NewBaseDetector("LAPS_PASSWORD_LEAKED", audit.CategoryAdvanced),
	}
}

// Detect executes the detection.
//
// This detector's twin, LAPS_PASSWORD_READABLE, had the same root cause fixed
// already - this detector was the forgotten sibling. It
// used to read Computer.LAPSPasswordExcessiveReaders, a field declared in
// pkg/types/user.go but never assigned anywhere in the collectors - always
// false, so the detector was structurally mute. The field has been removed
// (dead-and-unassigned is not a state to leave declared); the flag is now
// recomputed from data.ACLEntries instead, exactly as LAPS_PASSWORD_READABLE
// does - CONTROL_ACCESS + types.GUIDLAPSPassword
// on a grant ACE from a non-builtin-admin trustee is the same right
// Find-LapsADExtendedRights / Find-AdmPwdExtendedRights enumerates. The only
// difference from READABLE: "leaked / excessive readers" requires more than
// one distinct non-admin reader on the same computer - a single dedicated
// LAPS read-access group is the expected deployment shape and must not be
// flagged as excessive on its own (that's READABLE's job).
func (d *LapsPasswordLeakedDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	computerByDN := make(map[string]int, len(data.Computers))
	for i := range data.Computers {
		computerByDN[strings.ToLower(data.Computers[i].DN)] = i
	}

	readers := make(map[int]map[string]bool, len(data.Computers))
	for _, ace := range data.ACLEntries {
		if ace.ObjectType == "" || !strings.EqualFold(ace.ObjectType, types.GUIDLAPSPassword) {
			continue
		}
		if ace.AccessMask&types.MaskControlAccess == 0 {
			continue
		}
		if !audit.IsGrantACE(ace.AceType) {
			continue // a DENY/AUDIT ace grants nothing (DET_10 pattern)
		}
		if audit.IsBuiltinAdminTrustee(ace.Trustee) {
			continue // SYSTEM / Domain Admins / BUILTIN\Administrators etc. are expected
		}
		idx, ok := computerByDN[strings.ToLower(ace.ObjectDN)]
		if !ok || ace.Trustee == data.Computers[idx].ObjectSID {
			continue // unresolved target, or a self ACE
		}
		if readers[idx] == nil {
			readers[idx] = make(map[string]bool)
		}
		readers[idx][ace.Trustee] = true
	}

	var affected []types.Computer
	for i := range data.Computers {
		if len(readers[i]) > 1 {
			affected = append(affected, data.Computers[i])
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityLow,
		Category:    string(d.Category()),
		Title:       "LAPS Password Leaked",
		Description: "LAPS password visible to too many users. Reduces effectiveness of LAPS.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLapsPasswordLeakedDetector())
}
