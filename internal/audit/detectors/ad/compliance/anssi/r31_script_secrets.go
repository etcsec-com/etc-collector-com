package anssi

import (
	"context"
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
	"github.com/etcsec-com/etc-collector/pkg/types"
)

// ANSSI-PA-099 R31 — Traiter les risques liés aux secrets réutilisables
// figurant dans des scripts.
//
// Source: https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-admin_securisee_si_ad_v1-0%20(3).pdf
//
// Detector strategy: re-use the SYSVOLFindings collection produced by the
// existing SYSVOL scanner (cf. internal/providers/smb). The scanner already
// extracts files containing the "password=" / "secret=" patterns. We filter
// those by file extension (.ps1, .bat, .cmd, .vbs) to focus on scripts as
// opposed to GPP XML (which is covered by GPO_PASSWORD_IN_SYSVOL → R32).

type R31ScriptSecretsDetector struct{ audit.BaseDetector }

func NewR31ScriptSecretsDetector() *R31ScriptSecretsDetector {
	return &R31ScriptSecretsDetector{
		BaseDetector: audit.NewBaseDetector("ANSSI_R31_SCRIPT_SECRETS", audit.CategoryCompliance),
	}
}

func (d *R31ScriptSecretsDetector) Detect(_ context.Context, data *audit.DetectorData) []types.Finding {
	if len(data.SYSVOLFindings) == 0 {
		return nil
	}

	// v3.1.18 — filter on the dedicated Type emitted by the SYSVOL script
	// scanner (cf. smb.scanForScriptSecrets). v3.1.17's extension-only
	// filter caught nothing because the scanner only emitted GPP cpassword
	// findings — pure bullshit gap.
	var hits []audit.SYSVOLFinding
	for _, sf := range data.SYSVOLFindings {
		if strings.EqualFold(sf.Type, "script_secret") {
			hits = append(hits, sf)
		}
	}
	if len(hits) == 0 {
		return nil
	}

	var entities []types.AffectedEntity
	if data.IncludeDetails {
		for _, sf := range hits {
			name := sf.GPOName
			if name == "" {
				name = sf.GPOGUID
			}
			entities = append(entities, types.AffectedEntity{Type: "script", Name: name, DN: sf.FilePath})
		}
	}

	return wrapFinding(d, "ANSSI R31 — Reusable secrets found in SYSVOL scripts",
		"ANSSI R31 requires that reusable authentication secrets are not embedded in scripts. The SYSVOL scanner found cleartext credential patterns inside one or more script files (.ps1/.bat/.cmd/.vbs/...). Replace hardcoded secrets with a vault, gMSA, or runtime prompt.",
		types.SeverityHigh, len(hits), entities)
}

func init() {
	audit.MustRegister(NewR31ScriptSecretsDetector())
}
