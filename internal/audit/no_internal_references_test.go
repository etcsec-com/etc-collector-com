// No internal tracker references in shipped code.
//
// This code is source-available: someone outside the team reads it. A comment
// saying "T_NNN/CA_NO_LOCATION_BLOCK - before the fix, ..." is meaningless to
// them - it points at a ticket they cannot open, in a tracker they cannot see,
// and it makes the codebase look like a private notebook that was published by
// accident.
//
// Cleaning this up by hand after the fact does not work: it was done three
// times in one day, on three different deliveries, and each time some slipped
// through. This test moves the check to where the code is written, so the
// reference never reaches a commit.
//
// Test files were exempt at first, on the argument that a test naming the
// regression it pins documents something true. That argument does not survive
// the fact that the test files ship: they are in the published repository, a
// reader browsing it sees them, and the tracker number means no more to that
// reader there than anywhere else. What is useful is the DESCRIPTION of the
// regression, which costs nothing to keep. So the rule now covers every Go
// file, test files included.
package audit_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// internalReference matches the tracker's identifier shapes: a T or B, an
// underscore, three digits.
// Word-bounded, so a Go identifier like `errT_042` or a version string is not
// caught by accident.
var internalReference = regexp.MustCompile(`\b[TB]_\d{3}\b`)

// knownDebt lists the files that ALREADY carried internal references when this
// test was written (2026-09-08): 119 files, 358 lines. They are not
// excused - they are counted, so the debt has a size and an end.
//
// The test exists to stop the bleeding first. Hand-cleaning after each delivery
// was tried three times in one day and leaked every time; a blanket regex over
// the whole tree mangled sentences ("for as long as the process runs. wired").
// So: new files are held to zero from today, and this list only ever shrinks.
// Remove a file from here once it is clean - never add one.
// knownDebt is the number of internal references each file ALREADY carried when this
// test was written. Not a list of exemptions: a COUNT. A file may keep the references it
// has, and may only ever lose some.
//
// It started as a set of exempted files, and that was too weak: on the very next delivery
// four NEW references were added to files that were already on the list, and the test said
// nothing. Exempting a file exempts its future too. Counting does not.
// knownDebt is now EMPTY, and must stay that way.
//
// It once held 356 references across 117 shipped files. They were rewritten on
// 2026-09-08, one sentence at a time: the explanation each comment carried was
// kept, only the tracker number left. A blanket regex over the tree had been
// tried first and mangled sentences ("for as long as the process runs. wired"),
// which is why the second attempt read every line instead.
//
// A file may not reappear here. If this test fails, the fix is to write the
// comment without the number, never to add the file back.
var knownDebt = map[string]int{}

func TestNoInternalTrackerReferencesInShippedCode(t *testing.T) {
	// From internal/audit up to the module root.
	root := filepath.Join("..", "..")

	type hit struct {
		file string
		line int
		text string
	}
	var hits []hit

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			// Vendored code is not ours to edit; build output and VCS
			// metadata are not shipped source.
			case "vendor", ".git", "node_modules", "build", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Generated files are rewritten from the detector sources by
		// `make catalog`; a reference here is a symptom of one in the
		// source, and that source is what the test should point at.
		if strings.HasSuffix(info.Name(), "docs_gen.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(content), "\n") {
			if internalReference.MatchString(line) {
				rel, _ := filepath.Rel(root, path)
				hits = append(hits, hit{rel, i + 1, strings.TrimSpace(line)})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	// Compare per file against the tolerated count. A file over its count has
	// gained references since the baseline; a file under it has paid some back
	// and the baseline should be lowered to lock the gain in.
	parFichier := map[string][]hit{}
	for _, h := range hits {
		f := filepath.ToSlash(h.file)
		parFichier[f] = append(parFichier[f], h)
	}
	var nouveaux []hit
	var aBaisser []string
	for f, hs := range parFichier {
		tolere := knownDebt[f]
		if len(hs) > tolere {
			nouveaux = append(nouveaux, hs...)
		}
	}
	for f, tolere := range knownDebt {
		if len(parFichier[f]) < tolere {
			aBaisser = append(aBaisser, f)
		}
	}
	if len(aBaisser) > 0 {
		sort.Strings(aBaisser)
		t.Logf("%d file(s) now carry FEWER internal references than the baseline allows. "+
			"Lower their count in knownDebt so the gain cannot be undone silently:\n  %s",
			len(aBaisser), strings.Join(aBaisser, "\n  "))
	}
	if len(nouveaux) == 0 {
		return
	}
	hits = nouveaux

	var b strings.Builder
	b.WriteString("NEW internal tracker references in shipped Go files.\n")
	b.WriteString("This code is source-available: a reader outside the team cannot open these,\n")
	b.WriteString("and a comment that points at one tells them nothing. Say WHAT the code does and WHY,\n")
	b.WriteString("without the ticket number - the git history keeps the link.\n\n")
	for _, h := range hits {
		line := h.text
		if len(line) > 110 {
			line = line[:110] + "…"
		}
		b.WriteString("  " + h.file + ":" + itoa(h.line) + "  " + line + "\n")
	}
	t.Fatal(b.String())
}

// itoa avoids pulling strconv in for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d [20]byte
	i := len(d)
	for n > 0 {
		i--
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return string(d[i:])
}
