package main

import (
	"go/ast"
	"strings"
	"testing"
)

// TestLdapBindPasswordFlagWarnsOnEveryCommand — T_101 (server.go), extended by T_106
// to the 4 other commands that define the identical --ldap-bind-password flag
// (discover.go, audit.go, saas.go, service.go — found by grep while doing T_101, see
// M_020). The secret ends up in argv, readable by any local user via
// /proc/<pid>/cmdline (world-readable on Linux) for as long as the process runs —
// confirmed live on a lab host. Every command that accepts this flag must call this
// out loudly rather than silently accept it as equally safe as any alternative.
//
// T_106 note: unlike server.go, none of the 4 added commands read
// LDAP_BIND_PASSWORD/ldap.bindPassword back from viper for this flag (verified by
// reading every use of auditLDAPBindPass/daemonLDAPBindPass/svcLdapBindPass) — they
// use the firstNonEmpty/resolveLDAPConnFromSources helpers in audit.go instead.
// T_111 wired that fallback for discover ad and audit ad, which used to
// MarkFlagRequired the flag with no working env/config alternative at all; both now
// resolve LDAP_BIND_PASSWORD/ldap.bindPassword like server.go does. This test
// therefore only checks the flag name and the /proc/<pid>/cmdline exposure mechanism
// are named in the warning, not any specific alternative — each command's actual
// warning text differs accordingly (see the commands' source).
//
// Static AST check, matching this package's convention for run functions that start a
// real server/process or block — not a unit-test target. What's checked per command:
// an `if cmd.Flags().Changed("ldap-bind-password") { ... }` guard whose body logs a
// warning mentioning both the flag and the exposure mechanism. If you add a new
// command that defines this flag, add it to ldapBindPasswordCommands below.
func TestLdapBindPasswordFlagWarnsOnEveryCommand(t *testing.T) {
	ldapBindPasswordCommands := []struct {
		file, funcName string
	}{
		{"server.go", "runServer"},
		{"discover.go", "runDiscoverAD"},
		{"audit.go", "runAuditAD"},
		{"saas.go", "runDaemon"},
		{"service.go", "runServiceInstall"},
	}

	for _, c := range ldapBindPasswordCommands {
		t.Run(c.funcName, func(t *testing.T) {
			fn := findFunc(t, c.file, c.funcName)

			var found bool
			ast.Inspect(fn, func(n ast.Node) bool {
				ifStmt, ok := n.(*ast.IfStmt)
				if !ok {
					return true
				}
				if !condChecksFlagChanged(ifStmt.Cond, "ldap-bind-password") {
					return true
				}
				if bodyWarnsAbout(ifStmt.Body, "ldap-bind-password", "cmdline") {
					found = true
				}
				return true
			})

			if !found {
				t.Fatalf("%s in %s does not warn when --ldap-bind-password is explicitly "+
					"passed (expected an `if cmd.Flags().Changed(\"ldap-bind-password\")` guard whose "+
					"body logs a warning mentioning the flag and /proc/<pid>/cmdline exposure)",
					c.funcName, c.file)
			}
		})
	}
}

// condChecksFlagChanged reports whether expr contains a call to a method named
// "Changed" with a string-literal argument equal to flagName.
func condChecksFlagChanged(expr ast.Expr, flagName string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Changed" {
			return true
		}
		for _, arg := range call.Args {
			if lit, ok := arg.(*ast.BasicLit); ok && strings.Trim(lit.Value, `"`) == flagName {
				found = true
			}
		}
		return true
	})
	return found
}

// bodyWarnsAbout reports whether block contains a logging call (Warn/Warning) whose
// string-literal arguments together contain every substring in want.
func bodyWarnsAbout(block *ast.BlockStmt, want ...string) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !loggerMethodNames[sel.Sel.Name] {
			return true
		}
		var text strings.Builder
		for _, arg := range call.Args {
			if lit, ok := arg.(*ast.BasicLit); ok {
				text.WriteString(lit.Value)
			}
		}
		msg := text.String()
		for _, w := range want {
			if !strings.Contains(msg, w) {
				return true
			}
		}
		found = true
		return true
	})
	return found
}
