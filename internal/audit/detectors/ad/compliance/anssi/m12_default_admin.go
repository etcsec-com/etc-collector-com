package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI Guide d'hygiène M12 — Changer les éléments d'authentification par
// défaut sur les équipements et services.
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/guide_hygiene_informatique_anssi.pdf
//
// AD-side, the most visible "default authentication element" is the built-in
// Administrator account (RID 500). ANSSI recommends renaming it AND limiting
// its use; an account named "Administrator" / "Administrateur" is a low-effort
// target for password-spraying attacks since the name is a known-constant.

// M12DefaultAdminNotRenamedDetector flags the case where the built-in
// Administrator (RID 500) account still carries its default name. The check
// uses DomainInfo.AdminAccountName which is populated from the LDAP query
// against the well-known SID `<DomainSID>-500`.
type M12DefaultAdminNotRenamedDetector struct{ audit.BaseDetector }

func NewM12DefaultAdminNotRenamedDetector() *M12DefaultAdminNotRenamedDetector {
	return &M12DefaultAdminNotRenamedDetector{
		BaseDetector: audit.NewBaseDetector("M12_DEFAULT_ADMIN_NOT_RENAMED", audit.CategoryCompliance),
	}
}

func (d *M12DefaultAdminNotRenamedDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if data.DomainInfo == nil {
		return nil
	}
	name := strings.ToLower(strings.TrimSpace(data.DomainInfo.AdminAccountName))
	if name == "" {
		// Builtin admin account name not collected — don't emit a finding,
		// the audit is incomplete on this point but we must not invent one.
		return nil
	}

	// v3.1.18 — multi-locale list. Windows Server installs may use the
	// localized name of the built-in Administrator account in some legacy
	// languages, although modern installations always use "Administrator"
	// regardless of locale. We list the historical localizations to avoid
	// false negatives on older domains.
	defaultNames := map[string]bool{
		"administrator":            true, // EN (modern + most installs)
		"administrateur":           true, // FR
		"administrador":            true, // ES, PT
		"administrators":           true, // EN plural variant seen on legacy
		"amministratore":           true, // IT
		"rendszergazda":            true, // HU
		"administraator":           true, // ET / NL legacy
		"järjestelmänvalvoja":      true, // FI
		"administratör":            true, // SE
		"administrator (built-in)": true, // some Windows tooling outputs
	}
	if !defaultNames[name] {
		return nil // renamed → compliant with M12
	}

	return wrapFinding(d, "ANSSI Guide M12 — Built-in Administrator account is not renamed",
		"The RID-500 built-in Administrator account still carries its default name (\""+data.DomainInfo.AdminAccountName+"\"). "+
			"ANSSI Guide d'hygiène M12 recommends changing default authentication elements: a known-constant account name lowers the cost of password spraying and credential-stuffing attacks against the most privileged on-prem identity.",
		types.SeverityMedium, 1, nil)
}
