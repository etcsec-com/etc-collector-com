package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// R5SegregationDetector checks ANSSI PA-099 R7/R8 Tier segregation
// compliance. Name/ID kept as "R5" for backward compatibility (frozen by
// internal/audit/compliance/mappings.go, out of scope here),
// which already tags this detector's real controls as PA-099 R7 + R8 - R5 in
// PA-099 is "Identifier les valeurs métiers du Tier 1", unrelated to account
// segregation. R8 ("Cloisonner l'administration de chaque Tier", p.24-25)
// requires dedicated accounts per trust zone so that no account creates an
// attack path from one Tier to another of lower sensitivity; a single
// account holding membership in two different privileged-Tier groups
// (Domain Admins + Schema Admins, say) is exactly that path. R7
// ("Catégoriser les ressources du SI en Tiers") is the categorization
// prerequisite R8 builds on.
type R5SegregationDetector struct {
	audit.BaseDetector
}

// NewR5SegregationDetector creates a new detector
func NewR5SegregationDetector() *R5SegregationDetector {
	return &R5SegregationDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R5_SEGREGATION", audit.CategoryCompliance),
	}
}

// Detect executes the detection
func (d *R5SegregationDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var issues []string

	// Backup Operators is a domain-local Builtin group: a special principal
	// (Everyone/Authenticated Users) can be a member of it without that
	// membership EVER appearing in any real user's memberOf (Windows
	// computes it at logon, it never writes a back-link on a user object).
	// Without this, the loop below is structurally blind to that case no
	// matter the real state of the domain (R5/NIST_AC_6 confrontation).
	backupOpsOpenToAll := groupOpenToSpecialPrincipal(data.Groups, "backup operators")

	// Check for users in multiple privileged groups (no segregation)
	for _, u := range data.Users {
		if !u.Enabled() {
			continue
		}

		privilegedGroupCount := 0
		hasBackupOps := backupOpsOpenToAll
		for _, memberOf := range u.MemberOf {
			memberOfLower := strings.ToLower(memberOf)
			if strings.Contains(memberOfLower, "domain admins") ||
				strings.Contains(memberOfLower, "enterprise admins") ||
				strings.Contains(memberOfLower, "schema admins") ||
				strings.Contains(memberOfLower, "account operators") {
				privilegedGroupCount++
			}
			if strings.Contains(memberOfLower, "backup operators") {
				hasBackupOps = true
			}
		}
		if hasBackupOps {
			privilegedGroupCount++
		}

		if privilegedGroupCount > 1 {
			issues = append(issues, "Users in multiple privileged groups (no segregation)")
			break
		}
	}

	// A second check used to flag "standard users with admin
	// privileges" as users with AdminCount=true and no SPN, threshold >20.
	// Removed - it was self-contradictory (adminCount=true is set by the
	// adminSDHolder mechanism precisely BECAUSE the account is/was a member
	// of a protected/privileged group; PA-099 p.40 footnote 16 confirms this
	// explicitly), so it mislabeled privileged accounts as "standard users",
	// and the >20 threshold had no source (ANSSI or otherwise). No
	// replacement is substituted: retiring an unfounded, internally
	// inconsistent check rather than inventing a new one.

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "ANSSI PA-099 R7/R8 - Tier Segregation Non-Compliant",
		Description: "Privilege segregation does not meet ANSSI PA-099 R8 (\"Cloisonner l'administration de chaque Tier\", p.24-25): accounts, admin workstations and methods must not create attack paths from one Tier to a less sensitive one. A single account holding multiple privileged-Tier group memberships is such a path.",
		Count:       0,
	}

	if len(issues) > 0 {
		finding.Count = 1
		finding.Details = map[string]interface{}{
			"violations": issues,
			"framework":  "ANSSI-PA-099",
			"control":    "R7/R8",
		}
	}

	return []types.Finding{finding}
}

// groupOpenToSpecialPrincipal reports whether the group named groupName
// (matched case-insensitively against SAMAccountName/CN) has Everyone
// (S-1-1-0) or Authenticated Users (S-1-5-11) as a raw LDAP member - the
// same match used by GROUP_EVERYONE_IN_PRIVILEGED / GROUP_AUTHENTICATED_
// USERS_PRIVILEGED (groups/privileged package) to spot this exact pattern.
func groupOpenToSpecialPrincipal(groups []types.Group, groupName string) bool {
	for _, g := range groups {
		name := g.SAMAccountName
		if name == "" {
			name = g.CN
		}
		if !strings.EqualFold(name, groupName) {
			continue
		}
		for _, m := range g.Members {
			ml := strings.ToLower(m)
			if strings.Contains(ml, "everyone") || strings.Contains(m, "S-1-1-0") ||
				strings.Contains(ml, "authenticated users") || strings.Contains(m, "S-1-5-11") {
				return true
			}
		}
	}
	return false
}

func init() {
	audit.MustRegister(NewR5SegregationDetector())
}
