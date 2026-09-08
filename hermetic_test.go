package publicip

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The suite must be hermetic: it may talk to fake servers on loopback and to closed
// local ports, but it must never trigger a name resolution or send a packet off the
// machine.
//
// This matters more than it looks. A test that dials a hostname leaks a real DNS
// query to whoever's resolver the developer sits behind, and it still passes inside
// an isolated network namespace because the lookup merely fails there - so "the
// suite is green offline" is not evidence of hermeticity. Checking statically is the
// part that actually holds.
//
// Rule for new tests: an address fixture is an IP literal - loopback, or the
// documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 - never a
// hostname. A query name that is name-shaped on purpose (the payload a fake DNS
// server is asked about, never resolved) may opt out with a `// hermetic:allow`
// comment on the same line, which keeps every exception auditable.

// hermeticTestFiles discovers the suite instead of listing it, because a hardcoded list
// goes stale the first time a file is renamed - which is how this check nearly lost its
// teeth. hermetic_test.go itself is exempt: it has to name the files it checks, and
// "dns_test.go" is exactly the shape the scan looks for.
func hermeticTestFiles(t *testing.T) []string {
	t.Helper()

	local, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	files := make([]string, 0, len(local)+1)
	for _, name := range local {
		if name != "hermetic_test.go" {
			files = append(files, name)
		}
	}
	files = append(files, filepath.Join("cmd", "publicip", "main_test.go"))
	return files
}

func TestTestFixturesContainNoHostnames(t *testing.T) {
	for _, name := range hermeticTestFiles(t) {
		t.Run(name, func(t *testing.T) {
			for _, bad := range hostnamesInStrings(t, name) {
				t.Errorf("%s: string fixture %q would be resolved at runtime; "+
					"use an IP literal (loopback or 192.0.2.0/24) instead", name, bad)
			}
		})
	}
}

// TestDiscoveryTestsUseTheSandbox catches what the literal scan cannot: a test that
// builds a client with New() and then discovers through it reaches the shipped default
// servers, which are real public services, without any hostname appearing in the test
// file. Discovery must go through newTestClient, or through a client whose discoverers
// were replaced with stubs.
func TestDiscoveryTestsUseTheSandbox(t *testing.T) {
	for _, name := range hermeticTestFiles(t) {
		t.Run(name, func(t *testing.T) {
			for _, where := range bareNewInDiscoveryTests(t, name) {
				t.Errorf("%s: %s builds a client with New() and performs discovery; "+
					"use newTestClient(t, ...) so the default public endpoints are never dialed", name, where)
			}
		})
	}
}

// bareNewInDiscoveryTests returns "func:line" for each test function that both calls
// New() directly and calls a Discover method.
func bareNewInDiscoveryTests(t *testing.T, path string) []string {
	t.Helper()

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var found []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		callsNew, callsDiscover, viaSandbox := false, false, false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch target := call.Fun.(type) {
			case *ast.Ident:
				switch target.Name {
				case "New":
					callsNew = true
				case "newTestClient", "clientWith":
					viaSandbox = true
				}
			case *ast.SelectorExpr:
				if strings.HasPrefix(target.Sel.Name, "Discover") {
					callsDiscover = true
				}
			}
			return true
		})

		if callsNew && callsDiscover && !viaSandbox {
			found = append(found, fmt.Sprintf("%s:%d", fn.Name.Name, fset.Position(fn.Pos()).Line))
		}
	}
	return found
}

// TestResolvableNameClassification keeps the detector itself honest: it must catch
// the names that trigger a lookup and leave alone the address-shaped and file-shaped
// fixtures. Every entry in wantTrue is a string the suite used to contain.
func TestResolvableNameClassification(t *testing.T) {
	tests := []struct {
		value    string
		wantTrue bool
	}{
		// Needs a resolver.
		{"resolver1.opendns.com", true},
		{"myip.opendns.com", true},
		{"whoami.akamai.net", true},
		{"api.ipify.org", true},
		{"example.invalid", true},
		{"stun.invalid.test:3478", true},
		{"127.0.0.53:my.query", true},

		// Address or file shaped: no resolver involved.
		{"127.0.0.1", false},
		{"127.0.0.1:3478", false},
		{"192.0.2.1:53", false},
		{"::1", false},
		{"[::1]:1", false},
		{"2001:db8::dead", false},
		{"203.0.113.9", false},
		{"http://127.0.0.1:1", false},
		{"dns_test.go", false},
		{"cmd/publicip/main_test.go", false},
		{"cover.out", false},
		{"testdata/fuzz/seed", false},
		{"not-an-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := resolvableName(tt.value); got != tt.wantTrue {
			t.Errorf("resolvableName(%q) = %v, want %v", tt.value, got, tt.wantTrue)
		}
	}
}

// hostnamesInStrings returns the string literals of a Go file that carry a host name
// a resolver would have to look up. Prose (anything with whitespace) and IP literals
// are not addresses, so they are ignored.
func hostnamesInStrings(t *testing.T, path string) []string {
	t.Helper()

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	allowed := allowedLines(fset, f)

	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil || strings.ContainsAny(value, " \t\n") {
			return true // not an address fixture
		}
		if allowed[fset.Position(lit.Pos()).Line] {
			return true
		}
		for _, candidate := range addressNames(value) {
			if resolvableName(candidate) {
				found = append(found, value)
				return true
			}
		}
		return true
	})
	return found
}

// allowedLines collects the line numbers carrying a `hermetic:allow` comment.
func allowedLines(fset *token.FileSet, f *ast.File) map[int]bool {
	allowed := make(map[int]bool)
	for _, group := range f.Comments {
		for _, c := range group.List {
			if strings.Contains(c.Text, "hermetic:allow") {
				allowed[fset.Position(c.Pos()).Line] = true
			}
		}
	}
	return allowed
}

// addressNames extracts every part of a literal that a dialer would treat as a host:
// the URL host, the host of a host:port pair, and the bare value itself.
func addressNames(value string) []string {
	var out []string

	if u, err := url.Parse(value); err == nil && u.Host != "" {
		out = append(out, u.Hostname())
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		out = append(out, host)
	}
	return append(out, value)
}

// resolvableName reports whether s needs a resolver: it is not an IP literal, not a
// path, and the label after the last dot is an alphabetic TLD rather than a file
// extension. "dns_test.go" is a file name; "resolver.example.com" is a lookup.
func resolvableName(s string) bool {
	if s == "" || strings.ContainsAny(s, "/\\") || net.ParseIP(s) != nil {
		return false
	}
	last := strings.LastIndexByte(s, '.')
	if last < 0 {
		return false
	}
	label := s[last+1:]
	if i := strings.IndexAny(label, ":/?#"); i >= 0 {
		label = label[:i]
	}
	if len(label) < 2 {
		return false // an IPv4 literal leaves a single digit
	}
	if knownFileExtensions[strings.ToLower(label)] {
		return false
	}
	for i := 0; i < len(label); i++ {
		if !isLetter(label[i]) {
			return false
		}
	}
	return true
}

// knownFileExtensions are dotted suffixes that appear in test fixtures as file names
// and must not be mistaken for host names. "test" and "invalid" are deliberately
// absent: they are real lookup-prone TLDs.
var knownFileExtensions = map[string]bool{
	"go": true, "mod": true, "sum": true, "txt": true, "md": true, "json": true,
	"yml": true, "yaml": true, "out": true, "log": true, "sh": true, "exe": true,
	"html": true, "pem": true, "pcap": true, "profile": true,
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
