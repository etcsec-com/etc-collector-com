package gpo

import "github.com/etcsec-com/etc-collector/internal/audit"

// findUserRegistrySettingInt / findUserRegistrySettingString search the User
// Configuration registry hive (GPOPolicy.UserRegistrySettings) of every GPO.
//
// Attachment Manager's Folder-Options keys (DefaultFileTypeRisk,
// LowRiskFileTypes - AttachmentManager.admx, class="User") are written to
// User\Registry.pol, not Machine\Registry.pol, so
// helpers.FindRegistrySettingInt/String (which only ever searched
// GPOPolicy.RegistrySettings, the Machine hive) could never see them. Kept
// local to this package rather than added to internal/audit/helpers, since
// this lookup is meaningful only for the two folder-options detectors here.
func findUserRegistrySettingInt(policies map[string]*audit.GPOPolicy, getter func(*audit.RegistrySettings) *int) *int {
	for _, p := range policies {
		if p.UserRegistrySettings == nil {
			continue
		}
		if v := getter(p.UserRegistrySettings); v != nil {
			return v
		}
	}
	return nil
}

func findUserRegistrySettingString(policies map[string]*audit.GPOPolicy, getter func(*audit.RegistrySettings) *string) *string {
	for _, p := range policies {
		if p.UserRegistrySettings == nil {
			continue
		}
		if v := getter(p.UserRegistrySettings); v != nil {
			return v
		}
	}
	return nil
}
