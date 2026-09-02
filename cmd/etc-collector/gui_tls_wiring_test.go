package main

import (
	"go/ast"
	"testing"
)

// TestGUITLSResolvedOnEveryStartupPath — B_136 (T_060). Both functions that build the
// admin GUI's *config.Config and start listening (runServer, standalone;
// StartEmbeddedGUI, SaaS daemon — shared by the foreground `daemon` command and the
// Windows SaaS-daemon service) must call saas.ResolveGUITLS before starting the
// server, or a non-loopback bind silently serves plaintext HTTP again.
//
// Static AST check — these functions start real HTTP servers, none of that belongs in
// a unit test. The behaviour of ResolveGUITLS itself (loopback passthrough,
// already-configured passthrough, auto-generation, explicit opt-out, refusal on
// genuine failure) is covered directly in internal/saas/gui_tls_test.go.
func TestGUITLSResolvedOnEveryStartupPath(t *testing.T) {
	sites := []struct{ file, funcName string }{
		{"server.go", "runServer"},
		{"../../internal/saas/daemon.go", "(*Daemon).StartEmbeddedGUI"},
	}

	for _, site := range sites {
		t.Run(site.funcName, func(t *testing.T) {
			fn := findFunc(t, site.file, site.funcName)
			if !callsResolveGUITLS(fn) {
				t.Fatalf("%s in %s does not call ResolveGUITLS — a non-loopback bind would silently serve plaintext HTTP again",
					site.funcName, site.file)
			}
		})
	}
}

// callsResolveGUITLS reports whether fn calls (saas.)ResolveGUITLS anywhere in its
// body. Matches either a qualified call (saas.ResolveGUITLS, from cmd/etc-collector)
// or a bare one (ResolveGUITLS, from within package saas itself).
func callsResolveGUITLS(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.SelectorExpr:
			if f.Sel.Name == "ResolveGUITLS" {
				found = true
			}
		case *ast.Ident:
			if f.Name == "ResolveGUITLS" {
				found = true
			}
		}
		return true
	})
	return found
}

// TestServerCmd_HasHostFlag — B_136 (T_060): server.go's own --help text has always
// documented a --host flag; this locks down that the flag actually exists (it didn't,
// before this fix — the listen address was hardcoded to 0.0.0.0 regardless of what
// was passed) and defaults to loopback-only.
func TestServerCmd_HasHostFlag(t *testing.T) {
	flag := serverCmd.Flags().Lookup("host")
	if flag == nil {
		t.Fatal("serverCmd has no --host flag, despite documenting one in its help text")
	}
	if flag.DefValue != "127.0.0.1" {
		t.Fatalf("--host default = %q, want 127.0.0.1 (loopback-only by default)", flag.DefValue)
	}
}

// TestServerCmd_HasAllowInsecureHTTPFlag — the explicit, logged opt-out B_136 asks
// for, alongside TLS being required by default on a non-loopback host.
func TestServerCmd_HasAllowInsecureHTTPFlag(t *testing.T) {
	flag := serverCmd.Flags().Lookup("allow-insecure-http")
	if flag == nil {
		t.Fatal("serverCmd has no --allow-insecure-http opt-out flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("--allow-insecure-http default = %q, want false (TLS required by default)", flag.DefValue)
	}
}

// TestDaemonCmd_HasGuiAllowInsecureHTTPFlag — same opt-out, for the daemon command's
// --gui-host.
func TestDaemonCmd_HasGuiAllowInsecureHTTPFlag(t *testing.T) {
	flag := daemonCmd.Flags().Lookup("gui-allow-insecure-http")
	if flag == nil {
		t.Fatal("daemonCmd has no --gui-allow-insecure-http opt-out flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("--gui-allow-insecure-http default = %q, want false (TLS required by default)", flag.DefValue)
	}
}
