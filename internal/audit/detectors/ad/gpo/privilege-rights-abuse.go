package gpo

import (
	"context"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// Well-known safe SIDs that should have these privileges
var safePrivilegeSIDs = map[string]bool{
	"S-1-5-32-544": true, // BUILTIN\Administrators
	"S-1-5-18":     true, // LOCAL SYSTEM
	"S-1-5-19":     true, // LOCAL SERVICE
	"S-1-5-20":     true, // NETWORK SERVICE
}

func hasUnsafeSIDs(sids []string) []string {
	var unsafe []string
	for _, sid := range sids {
		if !safePrivilegeSIDs[sid] {
			unsafe = append(unsafe, sid)
		}
	}
	return unsafe
}

// SeDebugAbuseDetector checks if SeDebugPrivilege is assigned to non-admin accounts
type SeDebugAbuseDetector struct {
	audit.BaseDetector
}

func NewSeDebugAbuseDetector() *SeDebugAbuseDetector {
	return &SeDebugAbuseDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGE_SEDEBUG_ABUSE", audit.CategoryGPO),
	}
}

func (d *SeDebugAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "SeDebugPrivilege Assigned to Non-Administrators",
		Description: "The SeDebugPrivilege user right is assigned to accounts beyond the Administrators group. This privilege allows debugging any process, enabling credential extraction from LSASS memory, process injection, and full system compromise.",
		Count:       0,
	}

	sids := helpers.FindPrivilegeRight(data.GPOPolicies, func(pr *audit.PrivilegeRights) []string {
		return pr.SeDebugPrivilege
	})

	unsafe := hasUnsafeSIDs(sids)
	finding.Count = len(unsafe)
	if len(unsafe) > 0 {
		finding.Details = map[string]interface{}{
			"unsafeSIDs":     unsafe,
			"recommendation": "Remove SeDebugPrivilege from all accounts except the Administrators group.",
		}
	}

	return []types.Finding{finding}
}

// SeBackupAbuseDetector checks if SeBackupPrivilege is overly assigned
type SeBackupAbuseDetector struct {
	audit.BaseDetector
}

func NewSeBackupAbuseDetector() *SeBackupAbuseDetector {
	return &SeBackupAbuseDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGE_SEBACKUP_ABUSE", audit.CategoryGPO),
	}
}

func (d *SeBackupAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "SeBackupPrivilege Overly Assigned",
		Description: "The SeBackupPrivilege user right is assigned to accounts beyond Administrators and Backup Operators. This privilege allows reading any file on the system, bypassing all ACLs, enabling extraction of the NTDS.dit database, SAM hive, and other sensitive data.",
		Count:       0,
	}

	sids := helpers.FindPrivilegeRight(data.GPOPolicies, func(pr *audit.PrivilegeRights) []string {
		return pr.SeBackupPrivilege
	})

	// Also allow Backup Operators (S-1-5-32-551)
	safe := map[string]bool{
		"S-1-5-32-544": true, // Administrators
		"S-1-5-32-551": true, // Backup Operators
		"S-1-5-18":     true, // SYSTEM
	}
	var unsafe []string
	for _, sid := range sids {
		if !safe[sid] {
			unsafe = append(unsafe, sid)
		}
	}

	finding.Count = len(unsafe)
	if len(unsafe) > 0 {
		finding.Details = map[string]interface{}{
			"unsafeSIDs":     unsafe,
			"recommendation": "Limit SeBackupPrivilege to Administrators and Backup Operators only.",
		}
		if data.IncludeDetails {
			entities := make([]types.AffectedEntity, len(unsafe))
			for i, sid := range unsafe {
				entities[i] = audit.SIDToEntityWithCache(sid, data)
			}
			finding.AffectedEntities = entities
		}
	}

	return []types.Finding{finding}
}

// SeTcbAbuseDetector checks if SeTcbPrivilege (Act as OS) is assigned
type SeTcbAbuseDetector struct {
	audit.BaseDetector
}

func NewSeTcbAbuseDetector() *SeTcbAbuseDetector {
	return &SeTcbAbuseDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGE_SETCB_ABUSE", audit.CategoryGPO),
	}
}

func (d *SeTcbAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "SeTcbPrivilege (Act as Part of OS) Assigned",
		Description: "The SeTcbPrivilege (Act as part of the operating system) user right is assigned to user accounts. This privilege allows impersonating any user without authentication, equivalent to being SYSTEM. No user account should have this privilege.",
		Count:       0,
	}

	sids := helpers.FindPrivilegeRight(data.GPOPolicies, func(pr *audit.PrivilegeRights) []string {
		return pr.SeTcbPrivilege
	})

	// Only SYSTEM should have this
	var unsafe []string
	for _, sid := range sids {
		if sid != "S-1-5-18" { // Only SYSTEM is OK
			unsafe = append(unsafe, sid)
		}
	}

	finding.Count = len(unsafe)
	if len(unsafe) > 0 {
		finding.Details = map[string]interface{}{
			"unsafeSIDs":     unsafe,
			"recommendation": "Remove SeTcbPrivilege from all accounts. Only the SYSTEM account should have this privilege.",
		}
	}

	return []types.Finding{finding}
}

// SeRestoreAbuseDetector checks if SeRestorePrivilege is overly assigned
type SeRestoreAbuseDetector struct {
	audit.BaseDetector
}

func NewSeRestoreAbuseDetector() *SeRestoreAbuseDetector {
	return &SeRestoreAbuseDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGE_SERESTORE_ABUSE", audit.CategoryGPO),
	}
}

func (d *SeRestoreAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "SeRestorePrivilege Overly Assigned",
		Description: "The SeRestorePrivilege user right is assigned beyond Administrators and Backup Operators. This privilege allows writing to any file and registry key, bypassing ACLs, enabling DLL hijacking, service binary replacement, and other privilege escalation techniques.",
		Count:       0,
	}

	sids := helpers.FindPrivilegeRight(data.GPOPolicies, func(pr *audit.PrivilegeRights) []string {
		return pr.SeRestorePrivilege
	})

	safe := map[string]bool{
		"S-1-5-32-544": true, // Administrators
		"S-1-5-32-551": true, // Backup Operators
		"S-1-5-18":     true, // SYSTEM
	}
	var unsafe []string
	for _, sid := range sids {
		if !safe[sid] {
			unsafe = append(unsafe, sid)
		}
	}

	finding.Count = len(unsafe)
	if len(unsafe) > 0 {
		finding.Details = map[string]interface{}{
			"unsafeSIDs":     unsafe,
			"recommendation": "Limit SeRestorePrivilege to Administrators and Backup Operators only.",
		}
		if data.IncludeDetails {
			entities := make([]types.AffectedEntity, len(unsafe))
			for i, sid := range unsafe {
				entities[i] = audit.SIDToEntityWithCache(sid, data)
			}
			finding.AffectedEntities = entities
		}
	}

	return []types.Finding{finding}
}

// SeLoadDriverAbuseDetector checks if SeLoadDriverPrivilege is overly assigned
type SeLoadDriverAbuseDetector struct {
	audit.BaseDetector
}

func NewSeLoadDriverAbuseDetector() *SeLoadDriverAbuseDetector {
	return &SeLoadDriverAbuseDetector{
		BaseDetector: audit.NewBaseDetector("PRIVILEGE_SELOADDRIVER_ABUSE", audit.CategoryGPO),
	}
}

func (d *SeLoadDriverAbuseDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityCritical,
		Category:    string(d.Category()),
		Title:       "SeLoadDriverPrivilege Assigned to Non-Administrators",
		Description: "The SeLoadDriverPrivilege user right is assigned to accounts beyond Administrators. This privilege allows loading kernel-mode drivers, which can be abused to install rootkits, disable security software, and achieve full system compromise at the kernel level.",
		Count:       0,
	}

	sids := helpers.FindPrivilegeRight(data.GPOPolicies, func(pr *audit.PrivilegeRights) []string {
		return pr.SeLoadDriverPrivilege
	})

	unsafe := hasUnsafeSIDs(sids)
	finding.Count = len(unsafe)
	if len(unsafe) > 0 {
		finding.Details = map[string]interface{}{
			"unsafeSIDs":     unsafe,
			"recommendation": "Remove SeLoadDriverPrivilege from all non-administrator accounts.",
		}
		if data.IncludeDetails {
			entities := make([]types.AffectedEntity, len(unsafe))
			for i, sid := range unsafe {
				entities[i] = audit.SIDToEntityWithCache(sid, data)
			}
			finding.AffectedEntities = entities
		}
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSeDebugAbuseDetector())
	audit.MustRegister(NewSeBackupAbuseDetector())
	audit.MustRegister(NewSeTcbAbuseDetector())
	audit.MustRegister(NewSeRestoreAbuseDetector())
	audit.MustRegister(NewSeLoadDriverAbuseDetector())
}
