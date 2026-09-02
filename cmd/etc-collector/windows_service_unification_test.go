package main

import (
	"go/ast"
	"os"
	"strings"
	"testing"
)

// callsFunc reports whether fn's body contains a call to a bare identifier
// named funcName. Works by parsing source text, so it applies equally to
// //go:build windows files — this test runs on any platform.
func callsFunc(fn *ast.FuncDecl, funcName string) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == funcName {
			found = true
		}
		return true
	})
	return found
}

// referencesIdent reports whether fn's body references a bare identifier
// named name anywhere (as an argument, not necessarily a call).
func referencesIdent(fn *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			found = true
		}
		return true
	})
	return found
}

// TestRunServer_DelegatesToWindowsServiceHandler — B_184 (T_089). Verified
// live on DC01 before fixing: install_windows.go's installWindowsSCMService
// creates a Windows service whose ImagePath runs `<bin> server` directly,
// but runServer never called svc.Run — `sc start` on such a service failed
// with error 1053 (never responds to the SCM start request), even though
// the same binary serves requests fine run any other way (proven with a
// throwaway EtcSecTestServer service, removed after). This locks that
// runServer now detects SCM context and hands off correctly.
func TestRunServer_DelegatesToWindowsServiceHandler(t *testing.T) {
	fn := findFunc(t, "server.go", "runServer")
	if !callsFunc(fn, "isWindowsServiceContext") {
		t.Fatal("runServer does not call isWindowsServiceContext — the SCM integration gap would be back")
	}
	if !callsFunc(fn, "runServerAsWindowsService") {
		t.Fatal("runServer does not call runServerAsWindowsService")
	}
}

// TestInstallWindowsService_DelegatesToCanonicalSCMFunction — B_184 (T_089):
// a wiring lock mirroring TestServiceInstall_DelegatesToCanonicalUnitBuilder
// from T_087's Linux fix. installWindowsService (service_windows.go) used to
// hand-roll its own mgr.CreateService call under a divergent service name
// ("ETCCollector") — this proves it now delegates to the same
// installWindowsSCMService install_windows.go uses for `etc-collector
// install --mode server`, so both paths create one service under one name.
func TestInstallWindowsService_DelegatesToCanonicalSCMFunction(t *testing.T) {
	fn := findFunc(t, "service_windows.go", "installWindowsService")
	if !callsFunc(fn, "installWindowsSCMService") {
		t.Fatal("installWindowsService does not call installWindowsSCMService — service.go may be hand-rolling its own service creation again")
	}
}

// TestUninstallService_CleansUpLegacyName — B_184 (T_089). uninstallService
// must remove BOTH the canonical service (installServiceName,
// "EtcSecCollector") and, best-effort, any leftover from the old, divergent
// name (windowsServiceLegacyName, "ETCCollector") a prior binary version may
// have created — the ticket's own "piège": a Windows service left in the SCM
// survives a reboot, and DC01 hosts detector fixtures that a ghost service
// would pollute the picture for.
func TestUninstallService_CleansUpLegacyName(t *testing.T) {
	fn := findFunc(t, "service_windows.go", "uninstallService")
	if !referencesIdent(fn, "installServiceName") {
		t.Fatal("uninstallService does not reference installServiceName (the canonical service)")
	}
	if !referencesIdent(fn, "windowsServiceLegacyName") {
		t.Fatal("uninstallService does not reference windowsServiceLegacyName — a pre-existing ghost service under the old name would never be cleaned up")
	}
}

// TestRunService_DelegatesToServerHandler — B_184 (T_089). `etc-collector
// service run` (the Hidden command a pre-existing Windows service install
// may still have as its ImagePath) must dispatch to the SAME
// runServerAsWindowsService mechanism runServer's own SCM path now uses —
// not a second, independently-maintained copy.
func TestRunService_DelegatesToServerHandler(t *testing.T) {
	fn := findFunc(t, "service_windows.go", "runService")
	if !callsFunc(fn, "runServerAsWindowsService") {
		t.Fatal("runService does not call runServerAsWindowsService — the legacy entrypoint may be running its own separate copy of the SCM logic again")
	}
}

// TestWindowsServiceExecute_TolerantOfMissingLDAP — B_184 (T_089). Discovered
// live on DC01 while proving the SCM fix: windowsService.Execute treated a
// missing or unreachable LDAP config as FATAL (elog.Error + return true, 1),
// unlike runServer's own CLI path, which has always started successfully
// with no LDAP configured ("configure via GUI"). Reproduced live: a fresh
// Windows service instance with no LDAP set exited immediately
// (WIN32_EXIT_CODE 1066), which would have permanently blocked a
// GUI-driven LDAP setup on any fresh Windows server-mode install once
// runServerAsWindowsService made this code reachable from the canonical
// path. This checks for the empty-URL branch that makes startup tolerant
// rather than trying to prove a negative (no fatal return) by AST alone.
func TestWindowsServiceExecute_TolerantOfMissingLDAP(t *testing.T) {
	fn := findFunc(t, "service_windows.go", "(*windowsService).Execute")
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		sel, ok := bin.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "URL" {
			return true
		}
		if pkg, ok := sel.X.(*ast.SelectorExpr); ok && pkg.Sel.Name == "LDAP" {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("Execute has no cfg.LDAP.URL == \"\" check — it may require LDAP to be already configured just to start")
	}
}

// TestWindowsServiceLegacyNameConstantValue confirms the legacy constant's
// value is what DC01's own history actually used ("ETCCollector", verified
// live: `sc query ETCCollector` before this ticket's changes). A plain
// string search rather than AST — a const's value is a BasicLit, not a
// func, so findFunc doesn't apply.
func TestWindowsServiceLegacyNameConstantValue(t *testing.T) {
	data, err := os.ReadFile("service_windows.go")
	if err != nil {
		t.Fatalf("read service_windows.go: %v", err)
	}
	if !strings.Contains(string(data), `windowsServiceLegacyName = "ETCCollector"`) {
		t.Fatal(`expected const windowsServiceLegacyName = "ETCCollector" in service_windows.go`)
	}
}
