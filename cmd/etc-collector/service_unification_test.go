package main

import (
	"go/ast"
	"strings"
	"testing"
)

// TestBuildLinuxSystemdUnit_SameHardeningRegardlessOfMode — B_087 (T_087).
// Verified before fixing: the D6 audit's three cited call sites (install.go,
// scripts/install.sh, service.go) were re-checked against current code, not
// assumed stale. install.go and scripts/install.sh already agreed with each
// other (same unit name "etcsec-collector.service", same hardening block);
// service.go's `service install` was the sole outlier — a second,
// unhardened, differently-named unit ("etc-collector.service", ExecStart
// `server --port N`, WorkingDirectory=/opt/etc-collector, no hardening at
// all). Fixed by having service.go delegate to the same
// installLinuxSystemdService/buildLinuxSystemdUnit install.go already uses,
// instead of hand-rolling a second template that can drift again.
func TestBuildLinuxSystemdUnit_SameHardeningRegardlessOfMode(t *testing.T) {
	requiredHardening := []string{
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"PrivateTmp=yes",
		"ReadWritePaths=",
	}

	daemonUnit := buildLinuxSystemdUnit("/var/lib/etc-collector/bin/etc-collector", "/etc/etc-collector", "saas", "")
	serverUnit := buildLinuxSystemdUnit("/usr/local/bin/etc-collector", "/etc/etc-collector", "server", "--port 8443")

	for _, want := range requiredHardening {
		if !strings.Contains(daemonUnit, want) {
			t.Errorf("daemon-mode unit missing hardening directive %q:\n%s", want, daemonUnit)
		}
		if !strings.Contains(serverUnit, want) {
			t.Errorf("server-mode unit (service.go's call shape) missing hardening directive %q:\n%s", want, serverUnit)
		}
	}

	if !strings.Contains(serverUnit, "ExecStart=/usr/local/bin/etc-collector server --port 8443") {
		t.Errorf("server-mode ExecStart wrong or extraArgs (--port) dropped:\n%s", serverUnit)
	}
}

// TestServiceInstall_DelegatesToCanonicalUnitBuilder — B_087 (T_087), a
// wiring lock: static proof that installLinuxService (service.go, the
// former hand-rolled/unhardened outlier) actually calls
// installLinuxSystemdService (install.go's canonical function) rather than
// building its own unit text again.
func TestServiceInstall_DelegatesToCanonicalUnitBuilder(t *testing.T) {
	fn := findFunc(t, "service.go", "installLinuxService")

	callsCanonical := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "installLinuxSystemdService" {
			callsCanonical = true
		}
		return true
	})
	if !callsCanonical {
		t.Fatal("installLinuxService does not call installLinuxSystemdService — service.go may be hand-rolling its own unit again")
	}
}

// TestServiceLifecycleCommands_TargetCanonicalUnitName — B_087 (T_087). The
// service.go start/stop/status/uninstall helpers used to target the systemd
// unit "etc-collector" — a name that installLinuxService, once delegating to
// installLinuxSystemdService, no longer creates (that function always writes
// "etcsec-collector.service", linuxServiceFile). Locks that these commands
// were updated to match, so `service install` followed by `service start`
// operates on the SAME unit rather than one nothing ever creates.
func TestServiceLifecycleCommands_TargetCanonicalUnitName(t *testing.T) {
	for _, funcName := range []string{"startLinuxService", "stopLinuxService", "statusLinuxService", "uninstallLinuxService"} {
		t.Run(funcName, func(t *testing.T) {
			fn := findFunc(t, "service.go", funcName)

			targetsCanonical := false
			ast.Inspect(fn, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok {
					return true
				}
				if strings.Trim(lit.Value, `"`) == "etcsec-collector" {
					targetsCanonical = true
				}
				return true
			})
			if !targetsCanonical {
				t.Fatalf("%s does not reference the canonical unit name %q", funcName, "etcsec-collector")
			}
		})
	}
}
