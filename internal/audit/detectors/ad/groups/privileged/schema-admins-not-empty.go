package privileged

import (
	"context"
	"fmt"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// SchemaAdminsNotEmptyDetector flags when the Schema Admins or Enterprise
// Admins forest-level groups have members. Both should be empty outside
// active schema-change / forest-trust windows since members can make
// irreversible forest-wide changes (Schema Admins → schema modification;
// Enterprise Admins → forest configuration, intra-forest trust creation).
//
// v3.1.21 - extended from "Schema Admins only" to include Enterprise
// Admins, absorbing the scope of the deleted ANSSI_R17 detector. Detector
// ID kept for back-compat.
//
// This is NOT an ANSSI PA-099 requirement: the guide's R17 (p.35) is about
// timely patching of Tier 0 systems, and R23 (p.40) is about permissions
// applied TO Tier 0 accounts/groups (adminSDHolder-style ACL protection) -
// neither is about these groups' own membership being empty. Full-text
// search of PA-099 v1.0 finds no recommendation on this point. The source
// is Microsoft's own guidance:
//   - Schema Admins: "we recommend that the Schema Admins group remain
//     empty except when actively making changes" - Microsoft Learn,
//     "Remove all the members from the Schema Admins group unless you are
//     actively changing the schema" (services-hub/unified/health/
//     remediation-steps-ad).
//   - Enterprise Admins: "should contain no users on a day-to-day basis" -
//     Microsoft Learn, "Appendix E: Securing Enterprise Admins Groups in
//     Active Directory" (windows-server/identity/ad-ds/plan/
//     security-best-practices).
type SchemaAdminsNotEmptyDetector struct {
	audit.BaseDetector
}

func NewSchemaAdminsNotEmptyDetector() *SchemaAdminsNotEmptyDetector {
	return &SchemaAdminsNotEmptyDetector{
		BaseDetector: audit.NewBaseDetector("SCHEMA_ADMINS_NOT_EMPTY", audit.CategoryGroups),
	}
}

func (d *SchemaAdminsNotEmptyDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	var matched []types.Group
	totalMembers := 0
	for i := range data.Groups {
		name := strings.ToLower(data.Groups[i].SAMAccountName)
		if name == "schema admins" || name == "enterprise admins" {
			if len(data.Groups[i].Members) > 0 {
				matched = append(matched, data.Groups[i])
				totalMembers += len(data.Groups[i].Members)
			}
		}
	}

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Schema Admins or Enterprise Admins Group Is Not Empty",
		Description: fmt.Sprintf("Forest-level privileged groups (Schema Admins, Enterprise Admins) have %d total member(s) across %d group(s). These groups should remain empty in steady state and be populated on-demand only for forest-level operations (schema extension, intra-forest trust). Microsoft recommends the Schema Admins group remain empty except when actively changing the schema, and that Enterprise Admins contain no users on a day-to-day basis.", totalMembers, len(matched)),
		Count:       totalMembers,
	}

	if totalMembers > 0 && data.IncludeDetails {
		finding.AffectedEntities = helpers.ToAffectedGroupEntities(matched)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewSchemaAdminsNotEmptyDetector())
}
