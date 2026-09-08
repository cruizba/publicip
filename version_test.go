package publicip

import (
	"regexp"
	"testing"
)

// semverTag is what the release workflow writes into version.go. Matching the
// shape rather than a literal keeps the test valid across releases.
var semverTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

func TestGetVersionShape(t *testing.T) {
	got := GetVersion()
	if !semverTag.MatchString(got) {
		t.Errorf("GetVersion() = %q, want a vMAJOR.MINOR.PATCH tag", got)
	}
	if got != version {
		t.Errorf("GetVersion() = %q, want the package constant %q", got, version)
	}
}
