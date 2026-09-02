// Cataloggen extracts catalog metadata (Title, Description, Severity) from
// every detector under internal/audit/detectors/ and emits one docs_gen.go
// per detector package with `func (d *XDetector) Doc() audit.DetectorDoc`
// methods. After running, every detector that embeds audit.BaseDetector
// will satisfy the DocumentedDetector interface, enabling `make catalog`
// to regenerate the markdown catalogs from the binary itself.
//
// Run via:
//
//	go run ./tools/cataloggen
//
// or via `go generate ./...` once a //go:generate directive is added to
// the audit package.
//
// Idempotent: re-running overwrites docs_gen.go with the latest extraction.
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Build tag passed to subprocess builds. We always parse with the "pro"
// build tag set so Pro-only detectors are included in the generated output.
// (Files gated by `//go:build !pro` won't be parsed in pro mode and vice
// versa — we have to make a choice; pro is the superset.)
const buildTag = "pro"

const detectorsDir = "internal/audit/detectors"

// generatedFileBaseName is the file written into each detector package.
// Re-run of cataloggen overwrites it. Easy to diff against committed copy
// in CI to detect drift.
const generatedFileBaseName = "docs_gen.go"

// catalogedDetector is one struct found in the source tree.
type catalogedDetector struct {
	StructName  string // e.g. "BP039VBSOffDetector"
	Title       string // extracted from wrapFinding/Finding{}
	Description string // idem
	Severity    string // "SeverityMedium" / "SeverityHigh" / ...
	SourceFile  string // path relative to internal/audit/detectors/
}

// packageGen accumulates detectors per package directory before writing
// the docs_gen.go output.
type packageGen struct {
	PackageName string
	Dir         string
	Detectors   []catalogedDetector
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "cataloggen: ERROR:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := findRepoRoot()
	if err != nil {
		return err
	}
	target := filepath.Join(root, detectorsDir)

	pkgs := map[string]*packageGen{} // dir → pkg
	var unmigrated []string          // structs with extraction failures

	err = filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Skip the file we generate ourselves (idempotency).
		if filepath.Base(path) == generatedFileBaseName {
			return nil
		}
		pkgDir := filepath.Dir(path)
		gen := pkgs[pkgDir]
		if gen == nil {
			gen = &packageGen{Dir: pkgDir}
			pkgs[pkgDir] = gen
		}
		dets, pkgName, fails, perr := extractFromFile(path, target)
		if perr != nil {
			return fmt.Errorf("%s: %w", path, perr)
		}
		if pkgName != "" {
			gen.PackageName = pkgName
		}
		gen.Detectors = append(gen.Detectors, dets...)
		unmigrated = append(unmigrated, fails...)
		return nil
	})
	if err != nil {
		return err
	}

	// Sort + write each package's docs_gen.go.
	totalDetectors := 0
	pkgsWithDetectors := 0
	for _, gen := range pkgs {
		if len(gen.Detectors) == 0 {
			// Package has no detectors (or none that we could identify).
			// Remove any stale docs_gen.go that may exist.
			stale := filepath.Join(gen.Dir, generatedFileBaseName)
			if _, err := os.Stat(stale); err == nil {
				_ = os.Remove(stale)
			}
			continue
		}
		sort.Slice(gen.Detectors, func(i, j int) bool {
			return gen.Detectors[i].StructName < gen.Detectors[j].StructName
		})
		out := filepath.Join(gen.Dir, generatedFileBaseName)
		body, err := renderPackage(gen)
		if err != nil {
			return fmt.Errorf("render %s: %w", out, err)
		}
		if err := os.WriteFile(out, body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", out, err)
		}
		totalDetectors += len(gen.Detectors)
		pkgsWithDetectors++
	}

	fmt.Fprintf(os.Stderr, "cataloggen: wrote docs_gen.go in %d package(s) covering %d detector(s)\n",
		pkgsWithDetectors, totalDetectors)
	if len(unmigrated) > 0 {
		sort.Strings(unmigrated)
		fmt.Fprintf(os.Stderr, "cataloggen: WARN — %d struct(s) with empty/partial Doc() (will need manual override):\n", len(unmigrated))
		for _, u := range unmigrated {
			fmt.Fprintln(os.Stderr, "  ", u)
		}
	}
	return nil
}

// findRepoRoot returns the absolute path of the directory containing go.mod.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s upward", dir)
		}
		dir = parent
	}
}

// extractFromFile parses one .go file and returns the catalog metadata for
// every detector struct defined in it. `targetRoot` is the absolute path of
// internal/audit/detectors/ — used to compute SourceFile.
func extractFromFile(path, targetRoot string) (dets []catalogedDetector, pkgName string, unmigrated []string, err error) {
	fset := token.NewFileSet()
	// Parse without ParseComments to keep AST small; we don't need them.
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, "", nil, err
	}
	pkgName = f.Name.Name
	relSourceFile := relSource(path, targetRoot)

	// Pass 1 — discover detector struct names: any struct that embeds
	// audit.BaseDetector (or BaseDetector if same package, but detectors
	// always live in subpackages).
	detectorStructs := map[string]bool{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			if structEmbedsBaseDetector(st) {
				detectorStructs[ts.Name.Name] = true
			}
		}
	}
	if len(detectorStructs) == 0 {
		return nil, pkgName, nil, nil
	}

	// Pass 2 — locate Detect methods on each detector struct and extract.
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "Detect" || fd.Recv == nil || len(fd.Recv.List) != 1 {
			continue
		}
		recvType := receiverTypeName(fd.Recv.List[0].Type)
		if !detectorStructs[recvType] {
			continue
		}
		title, desc, sev, ok := extractMetadataFromBody(fd.Body)
		if !ok {
			unmigrated = append(unmigrated, fmt.Sprintf("%s: %s (no extractable wrapFinding/Finding{})", relSourceFile, recvType))
			// Emit a placeholder — better than silently skipping; the dev sees
			// "TODO_EXTRACTION_FAILED" in the catalog and fixes.
			dets = append(dets, catalogedDetector{
				StructName:  recvType,
				Title:       "TODO_EXTRACTION_FAILED",
				Description: "Doc() metadata could not be extracted automatically; edit cataloggen or override manually.",
				Severity:    "SeverityInfo",
				SourceFile:  relSourceFile,
			})
			continue
		}
		dets = append(dets, catalogedDetector{
			StructName:  recvType,
			Title:       title,
			Description: desc,
			Severity:    sev,
			SourceFile:  relSourceFile,
		})
	}
	return dets, pkgName, unmigrated, nil
}

// relSource turns an absolute file path into a path relative to
// internal/audit/detectors/ — that's the convention the AD/Azure catalogs
// use today.
func relSource(absPath, root string) string {
	rel, err := filepath.Rel(root, absPath)
	if err != nil {
		return absPath
	}
	return filepath.ToSlash(rel)
}

// structEmbedsBaseDetector returns true if the struct has an anonymous
// (embedded) audit.BaseDetector field.
func structEmbedsBaseDetector(st *ast.StructType) bool {
	if st.Fields == nil {
		return false
	}
	for _, f := range st.Fields.List {
		if len(f.Names) != 0 {
			continue // not embedded
		}
		// Anonymous field: f.Type is the embedded type expression
		if isBaseDetectorExpr(f.Type) {
			return true
		}
	}
	return false
}

func isBaseDetectorExpr(e ast.Expr) bool {
	// Strip pointer if present
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	switch t := e.(type) {
	case *ast.SelectorExpr:
		// audit.BaseDetector
		if id, ok := t.X.(*ast.Ident); ok && id.Name == "audit" && t.Sel.Name == "BaseDetector" {
			return true
		}
	case *ast.Ident:
		// BaseDetector (same package — uncommon for detectors but defensive)
		if t.Name == "BaseDetector" {
			return true
		}
	}
	return false
}

// receiverTypeName returns the bare struct name of a method receiver (strips
// pointer indirection).
func receiverTypeName(e ast.Expr) string {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// extractMetadataFromBody walks the Detect() method body to find the
// canonical Title/Description/Severity. Returns the WORST severity if
// multiple emit points exist.
func extractMetadataFromBody(body *ast.BlockStmt) (title, desc, sev string, ok bool) {
	if body == nil {
		return "", "", "", false
	}
	type candidate struct {
		title, desc, sev string
	}
	var cands []candidate

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			// Recognized "wrap-style" helpers: (d, title, description, severity, ...)
			// — wrapFinding/wrapFindingWithRepro (ANSSI), wrap (HDS, ...).
			fnName := callFuncName(node.Fun)
			if fnName == "wrapFinding" || fnName == "wrapFindingWithRepro" || fnName == "wrap" {
				if len(node.Args) >= 4 {
					t := stringValue(node.Args[1])
					d := stringValue(node.Args[2])
					s := severityIdent(node.Args[3])
					if t != "" || d != "" || s != "" {
						cands = append(cands, candidate{title: t, desc: d, sev: s})
					}
				}
			}
		case *ast.CompositeLit:
			// Match either explicit `types.Finding{...}` OR a type-inferred
			// composite (the inner literal in `[]types.Finding{{...}}`) that
			// looks like a Finding (has Title or Severity key). Without the
			// inferred-type fallback we'd miss ~13 detectors that use the
			// shorter slice-literal form.
			if !isTypesFinding(node.Type) && !looksLikeInlineFinding(node) {
				return true
			}
			var t, d, s string
			var tIdent, dIdent string
			for _, elt := range node.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				id, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch id.Name {
				case "Title":
					t = stringValue(kv.Value)
					if t == "" {
						if name, ok := kv.Value.(*ast.Ident); ok {
							tIdent = name.Name
						}
					}
				case "Description":
					d = stringValue(kv.Value)
					if d == "" {
						if name, ok := kv.Value.(*ast.Ident); ok {
							dIdent = name.Name
						}
					}
				case "Severity":
					s = severityIdent(kv.Value)
				}
			}
			// Resolve variable references by scanning the body for the LAST
			// literal assignment (covers "title := A; if X { title = B }" patterns).
			if t == "" && tIdent != "" {
				t = lastStringAssignment(body, tIdent)
			}
			if d == "" && dIdent != "" {
				d = lastStringAssignment(body, dIdent)
			}
			if t != "" || d != "" || s != "" {
				cands = append(cands, candidate{title: t, desc: d, sev: s})
			}
		}
		return true
	})

	if len(cands) == 0 {
		return "", "", "", false
	}

	// Pick the candidate with the worst severity. Tie-break by first-found.
	worstIdx := 0
	for i := 1; i < len(cands); i++ {
		if severityRank(cands[i].sev) > severityRank(cands[worstIdx].sev) {
			worstIdx = i
		}
	}
	chosen := cands[worstIdx]
	if chosen.sev == "" {
		// Fall back to scanning the entire body for the highest types.SeverityX
		// referenced anywhere — handles `severity := types.SeverityMedium; severity = types.SeverityHigh` patterns.
		chosen.sev = scanWorstSeverity(body)
	}
	if chosen.sev == "" {
		chosen.sev = "SeverityInfo"
	}
	return chosen.title, chosen.desc, chosen.sev, true
}

// callFuncName extracts the function name from a call expression's Fun.
// Returns the bare ident name for both `foo(...)` and `pkg.foo(...)`.
func callFuncName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

// isTypesFinding returns true if the type expression is `types.Finding` or
// `Finding` (same package).
func isTypesFinding(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		if id, ok := t.X.(*ast.Ident); ok && id.Name == "types" && t.Sel.Name == "Finding" {
			return true
		}
	case *ast.Ident:
		if t.Name == "Finding" {
			return true
		}
	}
	return false
}

// looksLikeInlineFinding returns true when the composite literal has no
// explicit type (Type == nil — type-inferred from context) AND its keyed
// elements include at least one Finding-typical key (Title or Severity).
// This catches the `return []types.Finding{{Title: ..., Severity: ...}}`
// shorthand used by ~13 stub detectors.
func looksLikeInlineFinding(node *ast.CompositeLit) bool {
	if node.Type != nil {
		return false
	}
	for _, elt := range node.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		id, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if id.Name == "Title" || id.Name == "Severity" {
			return true
		}
	}
	return false
}

// stringValue extracts a constant string from an expression. Handles:
//   - string literal "foo"
//   - fmt.Sprintf("format", ...) → returns the format string
//   - "a" + "b" + ... → returns the concatenation of literal parts
//
// Returns "" for variable references and other dynamic forms.
func stringValue(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.BasicLit:
		if t.Kind == token.STRING {
			s, err := strconv.Unquote(t.Value)
			if err == nil {
				return s
			}
		}
	case *ast.CallExpr:
		if callFuncName(t.Fun) == "Sprintf" && len(t.Args) >= 1 {
			return stringValue(t.Args[0])
		}
	case *ast.BinaryExpr:
		if t.Op == token.ADD {
			return stringValue(t.X) + stringValue(t.Y)
		}
	}
	return ""
}

// severityIdent extracts the Severity constant name from an expression like
// `types.SeverityHigh`. Returns "SeverityHigh" (without the package prefix).
// Returns "" for variable references.
func severityIdent(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		if id, ok := t.X.(*ast.Ident); ok && id.Name == "types" && strings.HasPrefix(t.Sel.Name, "Severity") {
			return t.Sel.Name
		}
	case *ast.Ident:
		// Could be a local variable holding a severity. We can't resolve that
		// here — return "" so caller falls back to body-wide scan.
		_ = t
	}
	return ""
}

// scanWorstSeverity walks the entire method body and returns the highest
// types.SeverityX constant referenced. Used when the wrapFinding call passes
// a variable that holds a conditional severity.
func scanWorstSeverity(body *ast.BlockStmt) string {
	worst := ""
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != "types" {
			return true
		}
		if !strings.HasPrefix(sel.Sel.Name, "Severity") {
			return true
		}
		if severityRank(sel.Sel.Name) > severityRank(worst) {
			worst = sel.Sel.Name
		}
		return true
	})
	return worst
}

// lastStringAssignment scans body for assignments to a variable named `name`
// where the RHS is a literal string (or fmt.Sprintf format) and returns the
// LAST such literal — handles patterns like:
//
//	title := "default"
//	if cond { title = "override" }
//
// Returns "" if no literal assignment found.
func lastStringAssignment(body *ast.BlockStmt, name string) string {
	var last string
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) != 1 || len(node.Rhs) != 1 {
				return true
			}
			id, ok := node.Lhs[0].(*ast.Ident)
			if !ok || id.Name != name {
				return true
			}
			if v := stringValue(node.Rhs[0]); v != "" {
				last = v
			}
		}
		return true
	})
	return last
}

func severityRank(s string) int {
	switch s {
	case "SeverityCritical":
		return 5
	case "SeverityHigh":
		return 4
	case "SeverityMedium":
		return 3
	case "SeverityLow":
		return 2
	case "SeverityInfo":
		return 1
	}
	return 0
}

// renderPackage produces the docs_gen.go content for one package.
func renderPackage(g *packageGen) ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, "// Code generated by tools/cataloggen; DO NOT EDIT.")
	fmt.Fprintln(&buf, "// Run `go generate ./...` (or `go run ./tools/cataloggen`) to regenerate.")
	fmt.Fprintln(&buf)
	fmt.Fprintf(&buf, "package %s\n\n", g.PackageName)
	fmt.Fprintln(&buf, "import (")
	fmt.Fprintln(&buf, "\t\"github.com/etcsec-com/etc-collector/internal/audit\"")
	fmt.Fprintln(&buf, "\t\"github.com/etcsec-com/etc-collector/pkg/types\"")
	fmt.Fprintln(&buf, ")")
	fmt.Fprintln(&buf)
	for _, det := range g.Detectors {
		fmt.Fprintf(&buf, "// Doc returns catalog metadata for %s.\n", det.StructName)
		fmt.Fprintf(&buf, "func (*%s) Doc() audit.DetectorDoc {\n", det.StructName)
		fmt.Fprintln(&buf, "\treturn audit.DetectorDoc{")
		fmt.Fprintf(&buf, "\t\tTitle:       %s,\n", strconv.Quote(det.Title))
		fmt.Fprintf(&buf, "\t\tDescription: %s,\n", strconv.Quote(det.Description))
		fmt.Fprintf(&buf, "\t\tSeverity:    types.%s,\n", det.Severity)
		fmt.Fprintf(&buf, "\t\tSourceFile:  %s,\n", strconv.Quote(det.SourceFile))
		fmt.Fprintln(&buf, "\t}")
		fmt.Fprintln(&buf, "}")
		fmt.Fprintln(&buf)
	}
	// gofmt for safety
	out, err := format.Source(buf.Bytes())
	if err != nil {
		// On format failure, return raw bytes so the dev can see the syntax issue.
		return buf.Bytes(), err
	}
	return out, nil
}
