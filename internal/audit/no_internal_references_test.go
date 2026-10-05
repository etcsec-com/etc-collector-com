// No internal tracker references, and no lab infrastructure data, in shipped
// code. Two boundaries, one file, because both protect the same thing: what
// is internal must not leave in the published mirror.
//
// This code is source-available: someone outside the team reads it. A comment
// saying "T_NNN/CA_NO_LOCATION_BLOCK - before the fix, ..." is meaningless to
// them - it points at a ticket they cannot open, in a tracker they cannot see,
// and it makes the codebase look like a private notebook that was published by
// accident. A comment carrying the lab's real domain or a private IP address
// is worse than meaningless: it maps part of somebody's live network to every
// reader.
//
// Cleaning this up by hand after the fact does not work: it was done three
// times in one day, on three different deliveries, and each time some slipped
// through. The lab's domain leaked the same way, independently, into three
// shipped files once already. This test moves both checks to where the code
// is written, so neither kind of reference reaches a commit.
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
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// internalReference matches the tracker's identifier shapes: a T or B, an
// underscore, three OR MORE digits. Tickets were numbered on three digits
// (T_NNN) at first and moved to five (T_NNNNN) later; a pattern fixed at
// exactly three digits stops matching the format the project moved to, and
// that is a hole, not a stricter check.
// Word-bounded, so a Go identifier like `errT_NNN` or a version string is not
// caught by accident.
var internalReference = regexp.MustCompile(`\b[TB]_\d{3,}\b`)

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
		b.WriteString("  " + h.file + ":" + strconv.Itoa(h.line) + "  " + line + "\n")
	}
	t.Fatal(b.String())
}

// labDomainsFile, if present, lists fully-qualified lab domain names that must
// never appear in shipped code - one per line, blank lines and lines starting
// with # ignored. It is deliberately kept OUTSIDE public/: this file, not this
// test, is where a real lab value would have to live, and this file is never
// mirrored out and never committed here either. Its absence - the default on
// any checkout that is not the lab's own, including this one right now - is
// not an error: the domain half of the guard below simply has nothing to
// check and says so instead of silently passing.
var labDomainsFile = filepath.Join("..", "..", "..", ".lab-domains.local.txt")

func loadLabDomains(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(labDomainsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("reading %s: %v", labDomainsFile, err)
	}
	var domains []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, line)
	}
	return domains
}

// labIPCandidate matches a run of 2 to 7 dot-separated numeric groups. A real
// IPv4 address always has exactly 4; matching a wider run first and checking
// the count in isPrivateIPv4 (rather than anchoring the regex at exactly 4
// groups) avoids mis-splitting a longer digit-dot sequence - this tree
// carries a CIS benchmark item number, six groups long, that embeds a
// valid-looking run of four groups part-way through. A regex anchored at
// exactly 4 groups would report that embedded run as an address; matching
// the full run and rejecting anything that is not exactly 4 groups long does
// not.
var labIPCandidate = regexp.MustCompile(`\b[0-9]{1,3}(?:\.[0-9]{1,3}){1,6}\b`)

// isPrivateIPv4 reports whether candidate is a syntactically valid IPv4
// address (four octets, 0-255) in one of the three standard RFC1918 private
// ranges: class A (prefix 10, /8), class B (prefix 172.16, /12), class C
// (prefix 192.168, /16). It carries no lab-specific value - it flags the
// SHAPE of a private address, not a particular one, so this half of the
// guard does not itself publish what it protects.
func isPrivateIPv4(candidate string) bool {
	parts := strings.Split(candidate, ".")
	if len(parts) != 4 {
		return false
	}
	octets := make([]int, 4)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
		octets[i] = n
	}
	switch {
	case octets[0] == 10:
		return true
	case octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31:
		return true
	case octets[0] == 192 && octets[1] == 168:
		return true
	}
	return false
}

// TestNoLabInfrastructureDataInShippedCode is the second boundary this file
// enforces: no lab domain and no private IPv4 address in shipped code. It
// combines two designs deliberately kept apart, per finding:
//
//   - Private IPv4 literals: a GENERIC pattern, always active, no lab value
//     hardcoded anywhere. Restricted to comment text (parsed with go/parser,
//     not a raw line scan): this codebase's own tests legitimately embed
//     RFC1918 addresses as fixture data - measured at 17 such literals across
//     5 files on this tree, none of them the lab's - and a raw line scan over
//     source, the way the tracker-reference test above works, would flag
//     every one. Scoping to actual comments measured zero hits on the same
//     tree (see docs/security-validation/results/public-hygiene-guard-t250/
//     VERDICT.md for both raw commands and both counts).
//   - Lab domain names: no generic pattern is attempted. A regex that matches
//     "looks like a domain" (label(.label)*.TLD) was measured on this same
//     tree and produced 2177 hits, almost all Go identifiers written
//     Type.Field (DetectorData.ObjectBySID, GPOPolicy.AdvancedAudit, ...) or
//     shipped filenames that happen to parse as label.TLD (CHECKS.yml,
//     VERDICT.md, GptTmpl.inf, Registry.pol) - see the same VERDICT.md for
//     the full breakdown. Excluding every such shape reliably, across 341
//     detectors' worth of comments that keeps growing, is not a fight worth
//     starting. Instead this half reads an exact, curated list of real domain
//     names from labDomainsFile, a file that lives outside public/ and is
//     absent by default - see that file's own doc comment above.
func TestNoLabInfrastructureDataInShippedCode(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()

	type hit struct {
		file string
		line int
		text string
		kind string
	}
	var hits []hit

	labDomains := loadLabDomains(t)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "vendor", ".git", "node_modules", "build", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(info.Name(), "docs_gen.go") {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}

		if len(labDomains) > 0 {
			content, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			for i, line := range strings.Split(string(content), "\n") {
				for _, d := range labDomains {
					if strings.Contains(line, d) {
						hits = append(hits, hit{rel, i + 1, strings.TrimSpace(line), "lab domain " + d})
					}
				}
			}
		}

		// go/parser failures (a file that does not build) are not this
		// test's job to report; the comment-scoped IP check simply skips it.
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			return nil
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				pos := fset.Position(c.Pos())
				for _, cand := range labIPCandidate.FindAllString(c.Text, -1) {
					if isPrivateIPv4(cand) {
						hits = append(hits, hit{rel, pos.Line, strings.TrimSpace(c.Text), "private IPv4 " + cand})
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	if labDomains == nil {
		t.Logf("lab-domain check SKIPPED: %s is absent. Expected on any checkout "+
			"that is not the lab's own, including the published mirror - this half "+
			"of the guard only hardens when that local file exists.", labDomainsFile)
	}

	if len(hits) == 0 {
		return
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].file != hits[j].file {
			return hits[i].file < hits[j].file
		}
		return hits[i].line < hits[j].line
	})

	var b strings.Builder
	b.WriteString("Lab infrastructure data found in shipped Go files.\n")
	b.WriteString("public/ is the source-available mirror: a real lab IP or domain here maps\n")
	b.WriteString("part of somebody's live network to anyone who reads the code.\n\n")
	for _, h := range hits {
		line := h.text
		if len(line) > 110 {
			line = line[:110] + "…"
		}
		b.WriteString("  " + h.file + ":" + strconv.Itoa(h.line) + "  [" + h.kind + "]  " + line + "\n")
	}
	t.Fatal(b.String())
}

// dnDomainSuffix matches the trailing chain of a distinguished name's DC=
// components: at least two "dc=<label>," repetitions followed by a final
// "dc=<label>", case-insensitively. This is deliberately NOT a generic
// "looks like a domain" pattern - see the design note above
// TestNoLabInfrastructureDataInShippedCode for why that was rejected (2177
// false hits on this tree). A DN's domain suffix has a distinctive, narrow
// syntax that a prose comment or a Go identifier essentially never produces
// by accident, which is what makes an ALLOWLIST design affordable here where
// it was not for domain-shaped text in general.
var dnDomainSuffix = regexp.MustCompile(`(?i)(?:dc=[A-Za-z0-9-]+,)+dc=[A-Za-z0-9-]+`)

// allowedDNDomains is the explicit, curated list of fictitious domains this
// test suite's fixtures already use. A DN domain suffix found in shipped code
// that is not on this list fails TestDNDomainsAreFictitious below - adding a
// new entry here is a deliberate, reviewed choice; reuse one already listed
// before adding another. None of these are real: this list is exactly what
// makes it safe to keep in shipped code, unlike labDomainsFile above (which
// exists precisely because its content must NOT ship).
var allowedDNDomains = map[string]bool{
	"example.com":      true,
	"test.local":       true,
	"corp.local":       true,
	"test.com":         true,
	"contoso.com":      true,
	"lab.local":        true,
	"x.y":              true,
	"priv.example.com": true,
	"acme.corp":        true,
	"evil.example":     true,
	"corp.com":         true,
	"attacker.test":    true,
	"domain.com":       true,
}

// dnDomainOf canonicalizes a matched DC= chain ("DC=Corp,DC=Local" or
// "dc=Example,dc=COM") into a lowercase dotted domain ("corp.local",
// "example.com") comparable against allowedDNDomains.
func dnDomainOf(match string) string {
	parts := strings.Split(match, ",")
	labels := make([]string, 0, len(parts))
	for _, p := range parts {
		if idx := strings.IndexByte(p, '='); idx >= 0 {
			p = p[idx+1:]
		}
		labels = append(labels, strings.ToLower(p))
	}
	return strings.Join(labels, ".")
}

// TestDNDomainsAreFictitious is the mechanical guard behind the publication
// rule: a distinguished name's domain component, found anywhere in a shipped
// .go file (test files included, docs_gen.go excepted - the same scope as
// TestNoInternalTrackerReferencesInShippedCode above), must be one of
// allowedDNDomains. A real lab or customer domain slipping into a DN fixture
// fails here instead of shipping.
func TestDNDomainsAreFictitious(t *testing.T) {
	root := filepath.Join("..", "..")

	type hit struct {
		file   string
		line   int
		domain string
		text   string
	}
	var hits []hit

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "vendor", ".git", "node_modules", "build", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(info.Name(), "docs_gen.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		for i, line := range strings.Split(string(content), "\n") {
			for _, m := range dnDomainSuffix.FindAllString(line, -1) {
				domain := dnDomainOf(m)
				if !allowedDNDomains[domain] {
					hits = append(hits, hit{rel, i + 1, domain, strings.TrimSpace(line)})
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	if len(hits) == 0 {
		return
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].file != hits[j].file {
			return hits[i].file < hits[j].file
		}
		return hits[i].line < hits[j].line
	})

	var b strings.Builder
	b.WriteString("Distinguished-name domain(s) not on the fictitious allowlist found in shipped Go files.\n")
	b.WriteString("Reuse one of the domains already listed in allowedDNDomains (this file) rather than\n")
	b.WriteString("introducing a new or, worse, real one.\n\n")
	for _, h := range hits {
		line := h.text
		if len(line) > 110 {
			line = line[:110] + "…"
		}
		b.WriteString("  " + h.file + ":" + strconv.Itoa(h.line) + "  [" + h.domain + "]  " + line + "\n")
	}
	t.Fatal(b.String())
}
