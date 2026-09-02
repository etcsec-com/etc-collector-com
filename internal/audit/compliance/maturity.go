package compliance

import (
	"sort"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

// maturityAxesANSSIPA099 defines the 5 axes of the ANSSI AD maturity index.
// Each axis groups a set of official PA-099 R-codes; the axis level is
// computed from the % of those controls that pass during this audit.
//
// Names are in English for product alignment. Controls reference the
// official ANSSI-PA-099 v1.0 R-codes (see catalogs/anssi_pa099.go).
var maturityAxesANSSIPA099 = []struct {
	Name     string
	Controls []string
}{
	{
		Name: "Password Policy",
		// R29 control of secret dissemination, R30/R30- local admin password rotation,
		// R40 fine-grained password policy for Tier 0, R41 krbtgt rotation,
		// R42 trust account password renewal, R43 sensitive computer account password,
		// R44 built-in administrator password strength.
		Controls: []string{"R29", "R30", "R30-", "R40", "R41", "R42", "R43", "R44"},
	},
	{
		Name: "Privileged Accounts & Tier Model",
		// R1 privileged access model, R2 protect each tier, R8 segregate admin per tier,
		// R10 minimize tier exposure, R12 fine-grained delegation, R20-R23 control paths,
		// R58 Tier 0 OU, R59 restrict policies on Tier 0 OU.
		Controls: []string{"R1", "R2", "R8", "R10", "R12", "R20", "R21", "R22", "R23", "R58", "R59"},
	},
	{
		Name: "Strong Authentication & Cryptography",
		// R66 preserve Kerberos pre-auth on Tier 0, R67 address absence of pre-auth,
		// R68 enable Kerberos armoring, R71 forbid NTLM on Tier 0, R72 harden NTLM,
		// R75/R76/R77 protect against NTLM relays.
		Controls: []string{"R66", "R67", "R67-", "R68", "R71", "R72", "R75", "R76", "R77"},
	},
	{
		Name: "Delegation & Trusts Hardening",
		// R24 harden outgoing extra-forest trusts, R25+ selective auth on outgoing trusts,
		// R26 forbid Kerberos delegation across incoming trusts,
		// R65 address Kerberos delegation risks, R69/R70 SPN secret exposure.
		Controls: []string{"R24", "R25+", "R26", "R65", "R69", "R70", "R70-"},
	},
	{
		Name: "Audit, Monitoring & Hardening",
		// R11 system/software hardening, R13 log and centralize, R14+ automatic detection,
		// R15-R19+ Windows hardening on Tier 0, R52 secure communication protocols,
		// R56 RODC, R57 RODC hardening, R62 use Credential Guard as defense in depth.
		Controls: []string{"R11", "R13", "R15", "R16", "R17", "R18", "R19+", "R52", "R56", "R57", "R62"},
	},
}

// computeMaturityAxes builds the per-axis maturity scoring for ANSSI_PA099.
// Returns nil for any other framework.
//
// Operates on the EvaluatedControls slice produced by CalculatePerFramework
// to know which controls passed/failed/manual/not_applicable in this audit.
func computeMaturityAxes(framework string, evaluated []types.EvaluatedControl) []types.MaturityAxis {
	if framework != FrameworkANSSIPA099 {
		return nil
	}

	// Index evaluated controls by code for O(1) lookup.
	evalByCode := map[string]types.EvaluatedControl{}
	for _, ec := range evaluated {
		evalByCode[ec.Code] = ec
	}

	axes := make([]types.MaturityAxis, 0, len(maturityAxesANSSIPA099))
	for _, def := range maturityAxesANSSIPA099 {
		// Filter to controls actually known to ETC (i.e., present in the
		// PA-099 catalog and either passed or failed — not manual/n.a.).
		knownInAxis := make([]string, 0, len(def.Controls))
		failed := make([]string, 0)
		for _, c := range def.Controls {
			ec, ok := evalByCode[c]
			if !ok {
				continue
			}
			if ec.Status != "passed" && ec.Status != "failed" {
				continue // skip manual / not_applicable for axis scoring
			}
			knownInAxis = append(knownInAxis, c)
			if ec.Status == "failed" {
				failed = append(failed, c)
			}
		}
		sort.Strings(failed)

		var coverage float64
		var level int
		if len(knownInAxis) == 0 {
			coverage = 0
			level = 0
		} else {
			coverage = float64(len(knownInAxis)-len(failed)) / float64(len(knownInAxis)) * 100
			// Map coverage to a 0-5 level (ANSSI maturity scale).
			switch {
			case coverage >= 95:
				level = 5
			case coverage >= 80:
				level = 4
			case coverage >= 60:
				level = 3
			case coverage >= 40:
				level = 2
			case coverage >= 20:
				level = 1
			default:
				level = 0
			}
		}

		axes = append(axes, types.MaturityAxis{
			Name:           def.Name,
			Level:          level,
			Coverage:       round1(coverage),
			Controls:       knownInAxis,
			FailedControls: failed,
		})
	}
	return axes
}
