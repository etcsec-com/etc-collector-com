package main

import (
	"go/ast"
	"testing"
	"time"
)

// TestResolveAuditAsOf — B_175 (T_067). Pure parsing: empty input is "use the real
// moment this audit runs" (the zero time, exactly RunOptions.AsOf's documented
// default in internal/audit/engine.go), a valid RFC3339 timestamp parses to the exact
// instant it names, and an invalid one is a clear error rather than a silently-ignored
// flag.
func TestResolveAuditAsOf(t *testing.T) {
	t.Run("empty input is the zero time (real-time default, unchanged)", func(t *testing.T) {
		got, err := resolveAuditAsOf("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.IsZero() {
			t.Fatalf("got %v, want the zero time", got)
		}
	})

	t.Run("a valid RFC3339 timestamp parses exactly", func(t *testing.T) {
		got, err := resolveAuditAsOf("2026-08-20T00:00:00Z")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
		if !got.Equal(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("parsing is deterministic — the same input always yields the same instant, regardless of when this runs", func(t *testing.T) {
		a, err := resolveAuditAsOf("2026-08-20T00:00:00Z")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		time.Sleep(2 * time.Millisecond) // a real amount of wall-clock time passes
		b, err := resolveAuditAsOf("2026-08-20T00:00:00Z")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !a.Equal(b) {
			t.Fatalf("the same --as-of input produced different instants across two calls: %v vs %v — this is exactly the divergence B_175 exists to close", a, b)
		}
	})

	t.Run("an invalid timestamp is a clear error, not a silently-dropped flag", func(t *testing.T) {
		if _, err := resolveAuditAsOf("not-a-date"); err == nil {
			t.Fatal("expected an error for a malformed --as-of value")
		}
	})

	t.Run("a bare date without a time is rejected — RFC3339 is the documented contract", func(t *testing.T) {
		if _, err := resolveAuditAsOf("2026-08-20"); err == nil {
			t.Fatal("expected an error: --as-of documents RFC3339, not a bare date")
		}
	})
}

// TestAuditCmd_HasAsOfFlag locks down that the flag actually exists and is registered
// on the parent auditCmd (inherited by every audit subcommand), not just on one.
func TestAuditCmd_HasAsOfFlag(t *testing.T) {
	flag := auditCmd.PersistentFlags().Lookup("as-of")
	if flag == nil {
		t.Fatal("auditCmd has no --as-of persistent flag")
	}
	if flag.DefValue != "" {
		t.Fatalf("--as-of default = %q, want empty (real-time default, unchanged behavior)", flag.DefValue)
	}
}

// TestAuditAsOfWiredIntoRunOptions — B_175 (T_067). Static AST check that both
// runAuditAD and runAuditAzure actually set RunOptions.AsOf from the parsed flag,
// rather than the flag existing but going nowhere. These functions dial real LDAP/
// Azure connections, so this is a wiring check, not an executed run.
func TestAuditAsOfWiredIntoRunOptions(t *testing.T) {
	for _, funcName := range []string{"runAuditAD", "runAuditAzure"} {
		t.Run(funcName, func(t *testing.T) {
			fn := findFunc(t, "audit.go", funcName)
			if !assignsRunOptionsAsOf(fn) {
				t.Fatalf("%s does not set RunOptions.AsOf — the --as-of flag would exist but have no effect", funcName)
			}
		})
	}
}

// assignsRunOptionsAsOf reports whether fn contains a composite literal field
// `AsOf: ...` inside an audit.RunOptions{...} construction.
func assignsRunOptionsAsOf(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "RunOptions" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "audit" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "AsOf" {
				found = true
			}
		}
		return true
	})
	return found
}
