package audit

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Tier 0 customer customization for ANSSI compliance scoring.
//
// File location: <configDir>/tier0_groups.yaml
//
// Format:
//
//	groups:
//	  - "CN=Acme-DA,OU=AcmeAdmins,DC=corp,DC=local"
//	ous:
//	  - "OU=AcmeT0,DC=corp,DC=local"
//	mgmt_systems:
//	  - "CN=ACME-SCCM01,OU=Servers,DC=corp,DC=local"
//	admin_forest_dns:
//	  - "esae.corp"
//
// v3.1.19 — addresses the v3.1.18 honest gap where Tier 0 detection relied
// on hardcoded group names + OU naming markers. Customers with non-standard
// naming conventions (Acme-T0, custom forests) can declare their perimeter
// explicitly without forking the code.
//
// Defined in package audit (not helpers) to avoid an import cycle: the
// helpers package depends on audit, so the loader must live where engine
// can reach it without crossing that boundary.

// Tier0ConfigFileName is the canonical filename. Located inside configDir
// (typically /etc/etc-collector/).
const Tier0ConfigFileName = "tier0_groups.yaml"

// Tier0YAMLConfig mirrors the on-disk YAML schema. Populated by
// LoadTier0Config and copied into DetectorData.Tier0Config (which is the
// Tier0HelperConfig struct used by detectors — same fields, different
// type to keep the audit/helpers boundary clean).
type Tier0YAMLConfig struct {
	Groups         []string `yaml:"groups"`
	OUs            []string `yaml:"ous"`
	MgmtSystems    []string `yaml:"mgmt_systems"`
	AdminForestDNS []string `yaml:"admin_forest_dns"`
}

// LoadTier0Config reads <configDir>/tier0_groups.yaml. Returns:
//   - (nil, nil) when the file is absent — no customization, use defaults
//   - (cfg, nil) on a valid parse
//   - (nil, err) on read/parse error so the caller can log it cleanly
//
// The audit engine logs errors as warnings and continues with defaults.
func LoadTier0Config(configDir string) (*Tier0YAMLConfig, error) {
	if configDir == "" {
		return nil, nil
	}
	path := filepath.Join(configDir, Tier0ConfigFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Tier0YAMLConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &cfg, nil
}
