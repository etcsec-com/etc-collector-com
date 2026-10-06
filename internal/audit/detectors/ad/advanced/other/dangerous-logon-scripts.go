package other

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// DangerousLogonScriptsDetector detects dangerous logon scripts
type DangerousLogonScriptsDetector struct {
	audit.BaseDetector
}

// NewDangerousLogonScriptsDetector creates a new detector
func NewDangerousLogonScriptsDetector() *DangerousLogonScriptsDetector {
	return &DangerousLogonScriptsDetector{
		BaseDetector: audit.NewBaseDetector("DANGEROUS_LOGON_SCRIPTS", audit.CategoryAdvanced),
	}
}

// Detect executes the detection.
//
// Scope: this only inspects the scriptPath string for a network-path prefix
// ("\\..." or "//..."). It does NOT read any file, share, or NTFS ACL - the
// collector queries AD over LDAP (internal/providers/ldap) and never
// enumerates SMB share/filesystem permissions, so there is no ACL data
// available to evaluate here. A previous version of this detector's
// description claimed to find "weak ACLs", which the code has never done;
// that claim has been removed below.
//
// No official Microsoft source was found stating that a UNC-style logon
// script path is inherently dangerous regardless of its ACL. The documented
// risk is the opposite: MITRE ATT&CK T1037.003 "Boot or Logon Autostart
// Execution: Network Logon Script" (attack.mitre.org/techniques/T1037/003/)
// describes the attack as requiring WRITE ACCESS to the script file/share -
// its own mitigation is "Restrict write access to logon scripts to specific
// administrators" - not the mere presence of a network path. A UNC path
// pointing at a properly-secured share (e.g. the default NETLOGON/SYSVOL
// ACL, which grants Authenticated Users read-only per
// learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/assign-logon-script-profile-local-user)
// is not a weakness by itself. This detector is therefore a precursor/review
// heuristic (an account worth checking), not a confirmed weak-ACL finding.
func (d *DangerousLogonScriptsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var affected []types.User

	for _, u := range data.Users {
		// Check if user has logon script configured pointing to network path
		if u.ScriptPath != "" {
			if strings.Contains(u.ScriptPath, "\\\\") || strings.HasPrefix(u.ScriptPath, "//") {
				affected = append(affected, u)
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityMedium,
		Category:    string(d.Category()),
		Title:       "Logon Script Configured With Network Path",
		Description: "This account's logon script (scriptPath) references a network location (a UNC-style path) rather than a name resolved relative to NETLOGON. This detector only inspects the path string - it does not read the file, share, or NTFS ACL protecting that script, so it cannot confirm whether the location is actually writable by non-administrators. Per MITRE ATT&CK T1037.003, the real risk requires write access to the script; treat this as a review/precursor indicator, not a confirmed weak-ACL finding.",
		Count:       len(affected),
	}

	if data.IncludeDetails && len(affected) > 0 {
		finding.AffectedEntities = helpers.ToAffectedUserEntities(affected)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewDangerousLogonScriptsDetector())
}
