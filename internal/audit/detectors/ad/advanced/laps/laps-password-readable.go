package laps

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// LapsPasswordReadableDetector detects LAPS passwords readable by non-admins
type LapsPasswordReadableDetector struct {
	audit.BaseDetector
}

// NewLapsPasswordReadableDetector creates a new detector
func NewLapsPasswordReadableDetector() *LapsPasswordReadableDetector {
	return &LapsPasswordReadableDetector{
		BaseDetector: audit.NewBaseDetector("LAPS_PASSWORD_READABLE", audit.CategoryAdvanced),
	}
}

// Detect executes the detection.
//
// Computer.LAPSPasswordReadableByNonAdmins is declared but
// never assigned anywhere in the collectors - this detector always read a
// permanently-false field and could never fire, even with LAPS deployed
// and a non-admin holding the read right. The signal is already
// collected: the LDAP provider pulls each computer's nTSecurityDescriptor
// into data.ACLEntries, and CONTROL_ACCESS + types.GUIDLAPSPassword on an
// ACE is the exact extended right the attack-graph BFS already classifies
// as RelReadLAPSPassword (internal/audit/attack_graph.go classifyACL).
// Recompute the flag from that instead of reading the unset field.
func (d *LapsPasswordReadableDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	computerByDN := make(map[string]int, len(data.Computers))
	for i := range data.Computers {
		computerByDN[strings.ToLower(data.Computers[i].DN)] = i
	}

	readable := make(map[int]bool, len(data.Computers))
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
		readable[idx] = true
	}

	var affected []types.Computer
	for i := range data.Computers {
		if readable[i] {
			affected = append(affected, data.Computers[i])
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "LAPS Password Readable",
		Description: "Non-admin users can read LAPS password attributes. Exposure of local admin passwords.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedComputerEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewLapsPasswordReadableDetector())
}
