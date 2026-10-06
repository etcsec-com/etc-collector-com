package gpo

import (
	"context"
	"testing"

	"github.com/etcsec-com/etc-collector/internal/audit"
)

// TestFolderOptionsScriptExec_UserHiveDefaultFileTypeRisk is the RED->GREEN
// case for a regression: DefaultFileTypeRisk (AttachmentManager.admx, class="User")
// is written by Windows to User\Registry.pol, which
// CollectGPOPolicies never parsed - only Machine\Registry.pol. A GPO
// weakening Attachment Manager exactly the way it is really deployed went
// completely undetected.
func TestFolderOptionsScriptExec_UserHiveDefaultFileTypeRisk(t *testing.T) {
	risk := 6152
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID}": {
				UserRegistrySettings: &audit.RegistrySettings{
					FolderOptionsDefaultFileTypeRisk: &risk,
				},
			},
		},
	}

	findings := NewFolderOptionsScriptExecDetector().Detect(context.Background(), data)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Count == 0 {
		t.Fatal("a User-hive DefaultFileTypeRisk=6152 must fire, got Count=0")
	}
}

// TestFolderOptionsScriptExec_UserHiveLowRiskFileTypes covers the second
// field, same hive.
func TestFolderOptionsScriptExec_UserHiveLowRiskFileTypes(t *testing.T) {
	lowRisk := ".hta;.js;.vbs"
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID}": {
				UserRegistrySettings: &audit.RegistrySettings{
					FolderOptionsLowRiskFileTypes: &lowRisk,
				},
			},
		},
	}

	findings := NewFolderOptionsScriptExecDetector().Detect(context.Background(), data)
	if findings[0].Count == 0 {
		t.Fatal("User-hive LowRiskFileTypes containing dangerous extensions must fire, got Count=0")
	}
}

// TestFolderOptionsScriptExec_MachineHiveStillFires guards the pre-existing
// path against regression.
func TestFolderOptionsScriptExec_MachineHiveStillFires(t *testing.T) {
	risk := 6152
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID}": {
				RegistrySettings: &audit.RegistrySettings{
					FolderOptionsDefaultFileTypeRisk: &risk,
				},
			},
		},
	}

	findings := NewFolderOptionsScriptExecDetector().Detect(context.Background(), data)
	if findings[0].Count == 0 {
		t.Fatal("the Machine-hive path must still fire, got Count=0")
	}
}

// TestFolderOptionsScriptExec_NoWeakeningDoesNotFire guards against
// over-firing once both hives are consulted.
func TestFolderOptionsScriptExec_NoWeakeningDoesNotFire(t *testing.T) {
	data := &audit.DetectorData{
		GPOPolicies: map[string]*audit.GPOPolicy{
			"{GUID}": {},
		},
	}

	findings := NewFolderOptionsScriptExecDetector().Detect(context.Background(), data)
	if findings[0].Count != 0 {
		t.Fatalf("no GPO weakens Attachment Manager, must not fire, got count=%d", findings[0].Count)
	}
}
