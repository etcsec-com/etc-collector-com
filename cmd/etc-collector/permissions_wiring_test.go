package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestPermissionHardeningWiredAtStartupAndUpgrade — B_042/T_041. saas.SecureDir
// tightens a preexisting 0755 config directory (proven live by
// internal/saas.TestSecureDir_TightensPreExistingDirectory), but it only ever ran
// inside CredentialStore.Save() — a daemon restart after an in-place binary swap, or
// `install --upgrade`, never called it, so a directory left at 0755 by a pre-A_004
// install stayed there forever.
//
// This is a static check, not an executed integration run: runInstallUpgrade and
// runDaemon touch real system paths (symlinks under /usr/local/bin, systemd units)
// that must never run against the machine building this test. It proves both
// entrypoints now call saas.SecureDir on their config directory before doing anything
// else, without actually invoking the risky rest of either function.
func TestPermissionHardeningWiredAtStartupAndUpgrade(t *testing.T) {
	assertCallsSecureDir := func(t *testing.T, file, funcName string) {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}

		var found bool
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Name.Name != funcName {
				return true
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "SecureDir" {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "saas" {
					found = true
				}
				return true
			})
			return false // don't descend into other top-level decls
		})

		if !found {
			t.Fatalf("%s in %s does not call saas.SecureDir — a preexisting 0755 directory "+
				"from a pre-A_004 install is never tightened by this entrypoint", funcName, file)
		}
	}

	assertCallsSecureDir(t, "saas.go", "runDaemon")
	assertCallsSecureDir(t, "install_migrate.go", "runInstallUpgrade")
}
