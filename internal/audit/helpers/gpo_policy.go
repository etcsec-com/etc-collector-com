package helpers

import (
	"strings"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// Well-known GPO GUIDs
const (
	DefaultDomainPolicyGUID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
	DefaultDCPolicyGUID     = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
)

// GetDefaultDomainPolicy returns the Default Domain Policy from the GPO policies map
func GetDefaultDomainPolicy(policies map[string]*audit.GPOPolicy) *audit.GPOPolicy {
	if policies == nil {
		return nil
	}
	for guid, p := range policies {
		if strings.EqualFold(guid, DefaultDomainPolicyGUID) {
			return p
		}
	}
	return nil
}

// GetDefaultDCPolicy returns the Default Domain Controllers Policy
func GetDefaultDCPolicy(policies map[string]*audit.GPOPolicy) *audit.GPOPolicy {
	if policies == nil {
		return nil
	}
	for guid, p := range policies {
		if strings.EqualFold(guid, DefaultDCPolicyGUID) {
			return p
		}
	}
	return nil
}

// GetKerberosPolicy returns the Kerberos Policy from the Default Domain Policy
func GetKerberosPolicy(policies map[string]*audit.GPOPolicy) *audit.KerberosPolicy {
	ddp := GetDefaultDomainPolicy(policies)
	if ddp != nil && ddp.KerberosPolicy != nil {
		return ddp.KerberosPolicy
	}
	// Fallback: search all GPOs
	for _, p := range policies {
		if p.KerberosPolicy != nil {
			return p.KerberosPolicy
		}
	}
	return nil
}

// GetEventAudit returns the Event Audit settings from any GPO
func GetEventAudit(policies map[string]*audit.GPOPolicy) *audit.EventAudit {
	ddp := GetDefaultDomainPolicy(policies)
	if ddp != nil && ddp.EventAudit != nil {
		return ddp.EventAudit
	}
	dcPolicy := GetDefaultDCPolicy(policies)
	if dcPolicy != nil && dcPolicy.EventAudit != nil {
		return dcPolicy.EventAudit
	}
	for _, p := range policies {
		if p.EventAudit != nil {
			return p.EventAudit
		}
	}
	return nil
}

// FindRegistrySettingString searches all GPO policies for a specific registry string setting
func FindRegistrySettingString(policies map[string]*audit.GPOPolicy, getter func(*audit.RegistrySettings) *string) *string {
	if policies == nil {
		return nil
	}
	dcPolicy := GetDefaultDCPolicy(policies)
	if dcPolicy != nil && dcPolicy.RegistrySettings != nil {
		if v := getter(dcPolicy.RegistrySettings); v != nil {
			return v
		}
	}
	ddp := GetDefaultDomainPolicy(policies)
	if ddp != nil && ddp.RegistrySettings != nil {
		if v := getter(ddp.RegistrySettings); v != nil {
			return v
		}
	}
	for _, p := range policies {
		if p.RegistrySettings != nil {
			if v := getter(p.RegistrySettings); v != nil {
				return v
			}
		}
	}
	return nil
}

// FindPrivilegeRight searches all GPO policies for a specific privilege right
func FindPrivilegeRight(policies map[string]*audit.GPOPolicy, getter func(*audit.PrivilegeRights) []string) []string {
	if policies == nil {
		return nil
	}
	dcPolicy := GetDefaultDCPolicy(policies)
	if dcPolicy != nil && dcPolicy.PrivilegeRights != nil {
		if v := getter(dcPolicy.PrivilegeRights); v != nil {
			return v
		}
	}
	ddp := GetDefaultDomainPolicy(policies)
	if ddp != nil && ddp.PrivilegeRights != nil {
		if v := getter(ddp.PrivilegeRights); v != nil {
			return v
		}
	}
	for _, p := range policies {
		if p.PrivilegeRights != nil {
			if v := getter(p.PrivilegeRights); v != nil {
				return v
			}
		}
	}
	return nil
}

// FindRegistrySettingInt searches all GPO policies for a specific registry DWORD setting
// getter extracts the setting from RegistrySettings, returns nil if not set
func FindRegistrySettingInt(policies map[string]*audit.GPOPolicy, getter func(*audit.RegistrySettings) *int) *int {
	if policies == nil {
		return nil
	}
	// Check DC policy first (signing settings typically set here)
	dcPolicy := GetDefaultDCPolicy(policies)
	if dcPolicy != nil && dcPolicy.RegistrySettings != nil {
		if v := getter(dcPolicy.RegistrySettings); v != nil {
			return v
		}
	}
	// Then default domain policy
	ddp := GetDefaultDomainPolicy(policies)
	if ddp != nil && ddp.RegistrySettings != nil {
		if v := getter(ddp.RegistrySettings); v != nil {
			return v
		}
	}
	// Then any GPO
	for _, p := range policies {
		if p.RegistrySettings != nil {
			if v := getter(p.RegistrySettings); v != nil {
				return v
			}
		}
	}
	return nil
}
