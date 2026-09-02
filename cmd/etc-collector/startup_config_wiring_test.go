package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestAuthTokenLifetimeAppliedOnEveryStartupPath — B_047 (T_048). The three places
// that build a *config.Config before starting the API server diverged: two silently
// kept config.Default()'s hardcoded 30-day tokenLifetime no matter what config.yaml
// said, and the third (the standalone Windows service) got it right by loading the
// file wholesale via config.Load. This is the second time a setting got wired on one
// startup path and lost on another (B_037/T_038 was the first) — a third time must be
// impossible to produce without a test catching it. If you add a fourth startup path
// that builds a *config.Config, add it to startupPaths below.
//
// Static check, not an executed run: these functions start real HTTP servers, touch
// signal handlers, and (for the Windows service) call svc.Run — none of that belongs
// in a unit test. What's checked is that each function either (a) explicitly assigns
// .Auth.TokenLifetime — the config.ResolveDuration idiom used in server.go and
// daemon.go — or (b) calls config.Load, which resolves the whole struct (including
// Auth) via the same CLI flag > env > config.yaml > default precedence
// (internal/config/precedence.go) — the idiom already correct in service_windows.go.
func TestAuthTokenLifetimeAppliedOnEveryStartupPath(t *testing.T) {
	startupPaths := []struct {
		file, funcName string
	}{
		{"server.go", "runServer"},                                      // standalone server, foreground
		{"service_windows.go", "(*windowsService).Execute"},             // standalone server, Windows service
		{"../../internal/saas/daemon.go", "(*Daemon).StartEmbeddedGUI"}, // SaaS daemon's embedded GUI — foreground `daemon` AND the Windows SaaS-daemon service both call this one function
	}

	for _, p := range startupPaths {
		t.Run(p.funcName, func(t *testing.T) {
			fn := findFunc(t, p.file, p.funcName)
			if assignsAuthTokenLifetime(fn) || callsConfigLoad(fn) {
				return
			}
			t.Fatalf("%s in %s does not resolve auth.tokenLifetime — it either needs an "+
				"explicit `cfg.Auth.TokenLifetime = config.ResolveDuration(...)` or a "+
				"`config.Load(...)` call, or it silently keeps config.Default()'s hardcoded value",
				p.funcName, p.file)
		})
	}
}

// findFunc parses file and returns the *ast.FuncDecl for name, which may be a bare
// function ("runServer") or a method in "(*Receiver).Method" form.
func findFunc(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	recv, method := splitMethodName(name)

	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if recv == "" {
			if fn.Name.Name == name && fn.Recv == nil {
				return fn
			}
			continue
		}
		if fn.Name.Name != method || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		if recvTypeName(fn.Recv.List[0].Type) == recv {
			return fn
		}
	}
	t.Fatalf("function %s not found in %s", name, file)
	return nil
}

// splitMethodName turns "(*windowsService).Execute" into ("windowsService", "Execute")
// and "runServer" into ("", "runServer").
func splitMethodName(name string) (recv, method string) {
	if len(name) == 0 || name[0] != '(' {
		return "", name
	}
	end := 0
	for i, c := range name {
		if c == ')' {
			end = i
			break
		}
	}
	recvExpr := name[1:end] // "*windowsService"
	for len(recvExpr) > 0 && recvExpr[0] == '*' {
		recvExpr = recvExpr[1:]
	}
	return recvExpr, name[end+2:] // skip ")."
}

func recvTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	default:
		return ""
	}
}

// assignsAuthTokenLifetime reports whether fn contains an assignment whose LHS is a
// selector chain ending in .Auth.TokenLifetime, on any receiver variable name.
func assignsAuthTokenLifetime(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if selectorEndsWith(lhs, "Auth", "TokenLifetime") {
				found = true
			}
		}
		return true
	})
	return found
}

// selectorEndsWith reports whether expr is a selector chain ending in ....suffix...,
// e.g. selectorEndsWith(x, "Auth", "TokenLifetime") matches `cfg.Auth.TokenLifetime`
// and `d.something.Auth.TokenLifetime` alike — only the trailing field names matter.
func selectorEndsWith(expr ast.Expr, suffix ...string) bool {
	for i := len(suffix) - 1; i >= 0; i-- {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != suffix[i] {
			return false
		}
		expr = sel.X
	}
	return true
}

// callsConfigLoad reports whether fn calls config.Load anywhere in its body.
func callsConfigLoad(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Load" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "config" {
			found = true
		}
		return true
	})
	return found
}
