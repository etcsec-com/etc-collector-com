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
// v3.1.21 — extended from "Schema Admins only" to include Enterprise
// Admins, absorbing the scope of the deleted ANSSI_R17 detector. Detector
// ID kept for back-compat. Maps to PingCastle P-SchemaAdmin + ANSSI R23
// (mappings.go) — R17 is the old internal numbering; the live mapping was
// already re-pointed to the official PA-099 R23 in the v3.1.14 re-mapping,
// this comment was just never updated to match (T_102).
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
		Description: fmt.Sprintf("Forest-level privileged groups (Schema Admins, Enterprise Admins) have %d total member(s) across %d group(s). These groups should remain empty in steady state and be populated on-demand only for forest-level operations (schema extension, intra-forest trust). ANSSI PA-099 R17.", totalMembers, len(matched)),
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
