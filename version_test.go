package publicip

import (
	"regexp"
	"testing"
)

// semverTag is what the release workflow writes into version.go. Matching the
// shape rather than a literal keeps the test valid across releases.
var semverTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

func TestVersionShape(t *testing.T) {
	got := Version()
	if !semverTag.MatchString(got) {
		t.Errorf("Version() = %q, want a vMAJOR.MINOR.PATCH tag", got)
	}
	if got != version {
		t.Errorf("Version() = %q, want the package constant %q", got, version)
	}
}
