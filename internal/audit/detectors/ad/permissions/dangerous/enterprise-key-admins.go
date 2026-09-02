package dangerous

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/internal/audit/helpers"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// EnterpriseKeyAdminsDetector detects Enterprise Key Admins with full access to domain
type EnterpriseKeyAdminsDetector struct {
	audit.BaseDetector
}

// NewEnterpriseKeyAdminsDetector creates a new detector
func NewEnterpriseKeyAdminsDetector() *EnterpriseKeyAdminsDetector {
	return &EnterpriseKeyAdminsDetector{
		BaseDetector: audit.NewBaseDetector("ENTERPRISE_KEY_ADMINS_FULL_ACCESS", audit.CategoryPermissions),
	}
}

// Detect executes the detection
func (d *EnterpriseKeyAdminsDetector) Detect(ctx context.Context, data *audit.DetectorData) []types.Finding {
	// msDS-KeyCredentialLink attribute GUID
	const keyCredentialLinkGUID = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
	// Enterprise Key Admins SID suffix
	const enterpriseKeyAdminsSuffix = "-527"
	// Full control mask for AD objects (all specific AD rights + standard
	// rights) — what GENERIC_ALL maps to when actually stored in an AD ACE
	// (T_088/B_185: dsacls /G ... GA writes this mapped form, not the raw
	// 0x10000000 bit alone; genericall.go already checks both for the same
	// reason).
	const adFullControl = 0x000f01ff

	var affected []types.ACLEntry

	for _, ace := range data.ACLEntries {
		if !strings.HasSuffix(ace.Trustee, enterpriseKeyAdminsSuffix) {
			continue
		}

		// Check for write property on msDS-KeyCredentialLink
		hasWriteKeyCredential := (ace.AccessMask&types.MaskWriteProperty) != 0 &&
			strings.ToLower(ace.ObjectType) == keyCredentialLinkGUID

		// Check for GenericAll (full control) — raw bit or its AD-mapped form.
		hasGenericAll := (ace.AccessMask&types.MaskGenericAll) != 0 ||
			(ace.AccessMask&adFullControl) == adFullControl

		if hasWriteKeyCredential || hasGenericAll {
			affected = append(affected, ace)
		}
	}

	uniqueObjects := helpers.GetUniqueObjects(affected)
	totalInstances := len(affected)

	finding := types.Finding{
		Type:        d.ID(),
		Severity:    types.SeverityHigh,
		Category:    string(d.Category()),
		Title:       "Enterprise Key Admins with Full Access to Domain",
		Description: "The Enterprise Key Admins group has write access to msDS-KeyCredentialLink attribute on domain objects. This allows Shadow Credentials attacks, enabling members to authenticate as any domain user or computer.",
		Count:       len(uniqueObjects),
		Details: map[string]interface{}{
			"risk":           "Shadow Credentials attacks allowing authentication as any domain principal.",
			"recommendation": "Restrict Enterprise Key Admins write access to msDS-KeyCredentialLink on domain objects.",
		},
	}

	if totalInstances != len(uniqueObjects) {
		finding.TotalInstances = totalInstances
	}

	if data.IncludeDetails && len(uniqueObjects) > 0 {
		finding.AffectedEntities = audit.GetUniqueObjectEntities(affected, data.ObjectByDN)
	}

	return []types.Finding{finding}
}

func init() {
	audit.MustRegister(NewEnterpriseKeyAdminsDetector())
}
