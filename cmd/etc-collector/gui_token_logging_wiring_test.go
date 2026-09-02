package main

import (
	"go/ast"
	"testing"
)

// loggerMethodNames are the method names used across this codebase's logging
// surfaces: zap-based *logger.Logger (Warn/Info/Error/Debug) and the Windows
// eventlog.Log interface (Warning/Error/Info).
var loggerMethodNames = map[string]bool{
	"Warn": true, "Warning": true, "Info": true, "Error": true, "Debug": true,
}

// TestGuiTokenNeverPassedToALoggingCall — B_135 (T_060). The exact mistake made when
// EnsureHash's auto-generation was added (T_041/T_045): the freshly generated
// plaintext token got concatenated straight into a Warn() call, which — because that
// logger also writes to collector.log — put the token on disk, retrievable by anyone
// who can reach the SaaS GET_LOGS command for this collector. guitoken.AnnounceFirstRun
// now owns showing the token to the operator (stdout + a dedicated 0600 file, see
// internal/guitoken/guitoken.go); this test locks that down structurally: `token` must
// never again appear as an argument to a logging call in any of the three functions
// that call guitoken.EnsureHash.
//
// Static AST check — these functions start real HTTP servers / call svc.Run, none of
// that belongs in a unit test.
func TestGuiTokenNeverPassedToALoggingCall(t *testing.T) {
	sites := []struct{ file, funcName string }{
		{"server.go", "runServer"},
		{"service_windows.go", "(*windowsService).Execute"},
		{"../../internal/saas/daemon.go", "(*Daemon).StartEmbeddedGUI"},
	}

	for _, site := range sites {
		t.Run(site.funcName, func(t *testing.T) {
			fn := findFunc(t, site.file, site.funcName)
			if violations := findTokenPassedToLogger(fn, "token"); len(violations) > 0 {
				t.Fatalf("%s in %s passes %q directly to a logging call at %v — it must only reach "+
					"guitoken.AnnounceFirstRun (and fmt.Println/Printf for interactive/console output)",
					site.funcName, site.file, "token", violations)
			}
		})
	}
}

// findTokenPassedToLogger walks fn and returns the source positions of every logging
// call (method name in loggerMethodNames) whose arguments contain an Ident named
// varName, directly or nested inside a larger expression (string concatenation,
// fmt.Sprintf, ...).
func findTokenPassedToLogger(fn *ast.FuncDecl, varName string) []int {
	var violations []int
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !loggerMethodNames[sel.Sel.Name] {
			return true
		}
		for _, arg := range call.Args {
			if containsIdent(arg, varName) {
				violations = append(violations, int(call.Pos()))
			}
		}
		return true
	})
	return violations
}

// containsIdent reports whether expr contains an *ast.Ident named name anywhere in
// its subtree.
func containsIdent(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return true
	})
	return found
}
