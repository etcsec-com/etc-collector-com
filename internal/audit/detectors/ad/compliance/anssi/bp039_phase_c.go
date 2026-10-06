package anssi

import (
	"github.com/etcsec-com/etc-collector/internal/audit"
)

// ANSSI-BP-039 - Mise en œuvre des fonctionnalités de sécurité de Windows 10
// reposant sur la virtualisation (R5, R6/R7, R8, R9, R10*/R10**, R13, R14).
//
// Source: https://cyber.gouv.fr/sites/default/files/2017/11/np_securisation_windows10_securite_reposant_sur_la_virtualisation_v1.pdf
//
// Each BP-039 detector now lives in its own file (bp039-*.go), one detector
// per file. This file only keeps the two helpers shared across them.

// gpoSetsAtLeast iterates GPOs and returns true when any policy has the named
// integer registry setting set to at least minVal. Helper used across BP-039
// detectors that all follow the same "is X enforced anywhere" pattern.
func gpoSetsAtLeast(data *audit.DetectorData, accessor func(*audit.RegistrySettings) *int, minVal int) bool {
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		v := accessor(p.RegistrySettings)
		if v != nil && *v >= minVal {
			return true
		}
	}
	return false
}

// gpoMaxValue iterates GPOs and returns the maximum value found for the named
// integer registry setting. Returns -1 if no GPO sets it. Used to evaluate
// "is the strongest setting in place" (e.g. LsaCfgFlags=2 for UEFI lock).
func gpoMaxValue(data *audit.DetectorData, accessor func(*audit.RegistrySettings) *int) int {
	max := -1
	for _, p := range data.GPOPolicies {
		if p == nil || p.RegistrySettings == nil {
			continue
		}
		v := accessor(p.RegistrySettings)
		if v != nil && *v > max {
			max = *v
		}
	}
	return max
}
