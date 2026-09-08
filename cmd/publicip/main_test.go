package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	publicip "github.com/cruizba/publicip/v2"
)

var semverTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// stub is a publicip.Discoverer that answers from a fixture table, so the CLI can be
// driven end to end without a network. Every test goes through stubClient, which is what
// keeps the hermetic guard satisfied: nothing here can reach the shipped defaults.
type stub struct {
	family string // "4", "6" or "" for both
	ip     string
	err    error
	delay  time.Duration
}

type stubMethod struct {
	method publicip.Method
	stub   stub
}

func (s stubMethod) Discover(ctx context.Context, version publicip.IPVersion) (publicip.Result, error) {
	if s.stub.delay > 0 {
		select {
		case <-time.After(s.stub.delay):
		case <-ctx.Done():
			return publicip.Result{}, publicip.NewDiscoveryError(nil, true)
		}
	}
	if s.stub.err != nil {
		return publicip.Result{}, s.stub.err
	}

	wanted := "4"
	if version == publicip.IPv6Only {
		wanted = "6"
	}
	if s.stub.family != "" && s.stub.family != wanted {
		return publicip.Result{}, publicip.NewDiscoveryError([]publicip.Failure{{
			Method: s.method, Target: "stub", Family: wanted, Err: errors.New("no answer for this family"),
		}}, false)
	}

	ip := net.ParseIP(s.stub.ip)
	found := publicip.IPv4Only
	if ip.To4() == nil {
		found = publicip.IPv6Only
	}
	return publicip.Result{IP: ip, Method: s.method, Version: found}, nil
}

// stubClient builds a Client whose three methods are backed by fixtures.
func stubClient(t *testing.T, entries ...stubMethod) func(opts ...publicip.Option) *publicip.Client {
	t.Helper()

	byMethod := map[publicip.Method]stub{}
	for _, e := range entries {
		byMethod[e.method] = e.stub
	}

	return func(opts ...publicip.Option) *publicip.Client {
		all := []publicip.Option{
			publicip.WithMethods(publicip.STUN, publicip.DNS, publicip.HTTP),
			publicip.WithTimeout(30 * time.Second),
		}
		for _, m := range []publicip.Method{publicip.STUN, publicip.DNS, publicip.HTTP} {
			s, ok := byMethod[m]
			if !ok {
				s = stub{err: publicip.NewDiscoveryError([]publicip.Failure{{
					Method: m, Target: "stub", Family: "4", Err: errors.New("nothing configured"),
				}}, false)}
			}
			all = append(all, publicip.WithMethod(m, stubMethod{method: m, stub: s}))
		}
		return publicip.New(append(all, opts...)...)
	}
}

// runCLI invokes run() and returns its error plus what it wrote.
func runCLI(t *testing.T, newClient func(...publicip.Option) *publicip.Client, args ...string) (err error, stdout, stderr string) {
	t.Helper()

	var out, errOut bytes.Buffer
	c := &cli{stdout: &out, stderr: &errOut, newClient: newClient}
	runErr := c.run(args)
	return runErr, out.String(), errOut.String()
}

func okClient(t *testing.T) func(...publicip.Option) *publicip.Client {
	t.Helper()
	return stubClient(t, stubMethod{
		method: publicip.STUN,
		stub:   stub{ip: "203.0.113.9"},
	})
}

func TestRunVersion(t *testing.T) {
	for _, arg := range []string{"--version", "-version"} {
		err, stdout, _ := runCLI(t, okClient(t), arg)
		if err != nil {
			t.Fatalf("%s: run() error = %v", arg, err)
		}
		if got := strings.TrimSpace(stdout); !semverTag.MatchString(got) {
			t.Errorf("%s printed %q, want a version tag", arg, got)
		}
	}
}

func TestRunHelp(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		err, _, stderr := runCLI(t, okClient(t), arg)
		if err != nil {
			t.Fatalf("%s: run() error = %v", arg, err)
		}
		if !strings.Contains(stderr, "Usage:") {
			t.Errorf("%s did not print usage: %q", arg, stderr)
		}
	}
}

func TestRunRejectsBadFlags(t *testing.T) {
	err, _, stderr := runCLI(t, okClient(t), "-nope")
	if err == nil {
		t.Fatal("run() = nil for an unknown flag, want an error")
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("usage was not printed on a flag error: %q", stderr)
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	tests := []struct {
		args    []string
		wantErr string
	}{
		{[]string{"-i", "5"}, "invalid ip-version"},
		{[]string{"-i", "banana"}, "invalid ip-version"},
		{[]string{"-m", "carrier-pigeon"}, "invalid method"},
		{[]string{"-t", "0"}, "invalid timeout"},
		{[]string{"-t", "-3"}, "invalid timeout"},
	}

	for _, tt := range tests {
		err, _, _ := runCLI(t, okClient(t), tt.args...)
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("run(%v) error = %v, want it to contain %q", tt.args, err, tt.wantErr)
		}
	}
}

func TestRunPrintsTheAddress(t *testing.T) {
	err, stdout, stderr := runCLI(t, okClient(t), "-m", "stun")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "203.0.113.9" {
		t.Errorf("stdout = %q, want the bare address for pipe use", got)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing without --verbose", stderr)
	}
}

func TestRunVerboseReportsProvenance(t *testing.T) {
	err, _, stderr := runCLI(t, okClient(t), "-m", "stun", "-v")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !strings.Contains(stderr, "stun/ipv4") {
		t.Errorf("stderr = %q, want the method and family that answered", stderr)
	}
}

func TestRunVersionSpecificPath(t *testing.T) {
	// -i 6 with a stub that only answers over v6 covers the DiscoverWithIPVersion arm of
	// discover(); -i 4 with a v4-only stub covers the plain Discover arm.
	client := stubClient(t, stubMethod{method: publicip.STUN, stub: stub{family: "6", ip: "2001:db8::7"}})
	err, stdout, _ := runCLI(t, client, "-i", "6", "-m", "stun")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "2001:db8::7" {
		t.Errorf("stdout = %q, want 2001:db8::7", got)
	}

	any := stubClient(t, stubMethod{method: publicip.DNS, stub: stub{ip: "198.51.100.4"}})
	err, stdout, _ = runCLI(t, any, "-m", "dns")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "198.51.100.4" {
		t.Errorf("stdout = %q, want 198.51.100.4", got)
	}

	// No method and no family: the plain Discover arm.
	general := stubClient(t, stubMethod{method: publicip.STUN, stub: stub{ip: "192.0.2.30"}})
	err, stdout, _ = runCLI(t, general)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "192.0.2.30" {
		t.Errorf("stdout = %q, want 192.0.2.30", got)
	}
}

func TestRunJSON(t *testing.T) {
	err, stdout, _ := runCLI(t, okClient(t), "-m", "stun", "--json")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}

	var out jsonOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("decoding %q: %v", stdout, err)
	}
	if len(out.Addresses) != 1 {
		t.Fatalf("addresses = %d, want 1", len(out.Addresses))
	}
	got := out.Addresses[0]
	if got.IP != "203.0.113.9" || got.Method != "stun" || got.Family != "ipv4" {
		t.Errorf("address = %+v, want 203.0.113.9 over stun/ipv4", got)
	}
	if got.Latency == "" {
		t.Error("latency is empty, want the measured duration")
	}
}

func TestRunFailsWithTheFrozenMessage(t *testing.T) {
	failing := stubClient(t) // nothing configured for any method
	err, stdout, _ := runCLI(t, failing, "-m", "stun")
	if err == nil {
		t.Fatal("run() = nil, want a discovery failure")
	}
	if !strings.Contains(err.Error(), "no public IP") {
		t.Errorf("error = %q, want the not-found message", err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing printed on failure", stdout)
	}
}

func TestRunVerboseExplainsTheFailure(t *testing.T) {
	failing := stubClient(t)
	err, _, stderr := runCLI(t, failing, "-m", "stun", "-v")
	if err == nil {
		t.Fatal("run() = nil, want a failure")
	}
	if !strings.Contains(stderr, "attempts:") || !strings.Contains(stderr, "nothing configured") {
		t.Errorf("stderr = %q, want the per-target report that makes the failure actionable", stderr)
	}
}

func TestRunVerboseWithForeignErrorDoesNotPrintAttempts(t *testing.T) {
	// A discoverer returning a plain error has no Failure list to show; describeFailure
	// must stay quiet rather than print an empty heading.
	plain := stubClient(t, stubMethod{method: publicip.STUN, stub: stub{err: errors.New("boom")}})
	err, _, stderr := runCLI(t, plain, "-m", "stun", "-v")
	if err == nil {
		t.Fatal("run() = nil, want a failure")
	}
	if strings.Contains(stderr, "attempts:") {
		t.Errorf("stderr = %q, want no attempt list for a non-aggregated error", stderr)
	}
}

func TestRunAllCollectsEveryDistinctAddress(t *testing.T) {
	client := stubClient(t,
		stubMethod{method: publicip.STUN, stub: stub{ip: "203.0.113.9"}},
		stubMethod{method: publicip.DNS, stub: stub{ip: "203.0.113.9"}}, // same address
		stubMethod{method: publicip.HTTP, stub: stub{family: "6", ip: "2001:db8::9"}},
	)

	err, stdout, _ := runCLI(t, client, "-a")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	lines := strings.Fields(strings.TrimSpace(stdout))
	if len(lines) != 2 {
		t.Fatalf("stdout = %q, want two distinct addresses", stdout)
	}
	// IPv6 is probed first, so it leads.
	if lines[0] != "2001:db8::9" || lines[1] != "203.0.113.9" {
		t.Errorf("addresses = %v, want the v6 answer first", lines)
	}
}

func TestRunAllJSONWithPartialFailures(t *testing.T) {
	client := stubClient(t,
		stubMethod{method: publicip.STUN, stub: stub{ip: "192.0.2.11"}},
	)

	err, stdout, _ := runCLI(t, client, "-a", "-j", "-v")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	var out jsonOutput
	if e := json.Unmarshal([]byte(stdout), &out); e != nil {
		t.Fatalf("decoding %q: %v", stdout, e)
	}
	if len(out.Addresses) != 1 || out.Addresses[0].IP != "192.0.2.11" {
		t.Errorf("addresses = %+v, want the one that answered", out.Addresses)
	}
	if len(out.Errors) == 0 {
		t.Error("errors is empty, want the failed probes reported in verbose mode")
	}
}

func TestRunAllWithNothingFound(t *testing.T) {
	client := stubClient(t,
		stubMethod{method: publicip.STUN, stub: stub{err: errors.New("unreachable")}},
	)

	err, stdout, stderr := runCLI(t, client, "-a", "-v")
	if err == nil || !strings.Contains(err.Error(), "no public IP") {
		t.Fatalf("run() error = %v, want the not-found failure", err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	if !strings.Contains(stderr, "unreachable") {
		t.Errorf("stderr = %q, want the first cause of each failure", stderr)
	}
}

func TestRunAllStopsWhenTheBudgetRunsOut(t *testing.T) {
	client := stubClient(t, stubMethod{
		method: publicip.STUN,
		stub:   stub{ip: "203.0.113.9", delay: 2 * time.Second},
	})

	// One second of budget against a two second probe: the run must surface the budget
	// rather than report the remaining probes as if they had been tried.
	err, stdout, stderr := runCLI(t, client, "-a", "-v", "-t", "1")
	if err == nil {
		t.Fatalf("run() = nil with stdout %q; want the budget failure", stdout)
	}
	if !strings.Contains(stderr, "budget ran out") {
		t.Errorf("stderr = %q, want the exhausted budget named", stderr)
	}
}

func TestRunJSONPropagatesWriterErrors(t *testing.T) {
	// A writer that fails turns the JSON path into an error rather than a silent
	// half-written document.
	c := &cli{stdout: failingWriter{}, stderr: io.Discard, newClient: okClient(t)}
	if runErr := c.run([]string{"-m", "stun", "--json"}); runErr == nil {
		t.Fatal("run() = nil, want the write error to surface")
	} else if !strings.Contains(runErr.Error(), "cannot write") {
		t.Errorf("error = %v, want the writer's own error", runErr)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("cannot write") }

func TestParseHelpers(t *testing.T) {
	t.Run("parseVersion", func(t *testing.T) {
		for raw, want := range map[string]publicip.IPVersion{
			"":  publicip.Any,
			"4": publicip.IPv4Only,
			"6": publicip.IPv6Only,
		} {
			if got, err := parseVersion(raw); err != nil || got != want {
				t.Errorf("parseVersion(%q) = %v, %v; want %v", raw, got, err, want)
			}
		}
		if _, err := parseVersion("5"); err == nil {
			t.Error("parseVersion(5) = nil error, want a rejection")
		}
	})

	t.Run("parseMethod", func(t *testing.T) {
		for raw, want := range map[string]publicip.Method{
			"":     "",
			"stun": publicip.STUN,
			"dns":  publicip.DNS,
			"http": publicip.HTTP,
			"DNS":  publicip.DNS, // case is not significant
		} {
			if got, err := parseMethod(raw); err != nil || got != want {
				t.Errorf("parseMethod(%q) = %q, %v; want %q", raw, got, err, want)
			}
		}
		if _, err := parseMethod("ping"); err == nil {
			t.Error("parseMethod(ping) = nil error, want a rejection")
		}
	})

	t.Run("labels", func(t *testing.T) {
		if familyLabel(publicip.IPv6Only) != "6" || familyLabel(publicip.IPv4Only) != "4" {
			t.Error("familyLabel disagrees with the CLI's ipv4/ipv6 wording")
		}
		if versionLabel(publicip.IPv6Only) != "ipv6" || versionLabel(publicip.Any) != "ipv4" {
			t.Error("versionLabel is wrong")
		}
	})

	t.Run("firstCause", func(t *testing.T) {
		plain := errors.New("plain")
		if got := firstCause(plain); got != "plain" {
			t.Errorf("firstCause(plain) = %q, want the error's own text", got)
		}
		empty := publicip.NewDiscoveryError(nil, false)
		if got := firstCause(empty); !strings.Contains(got, "no public IP") {
			t.Errorf("firstCause(aggregated with no failures) = %q, want the aggregate text", got)
		}
	})
}

func TestRunBranchesWithoutAMethod(t *testing.T) {
	// -i without -m must take the family-specific call rather than the generic one.
	v6 := stubClient(t, stubMethod{method: publicip.STUN, stub: stub{family: "6", ip: "2001:db8::1"}})
	err, stdout, _ := runCLI(t, v6, "-i", "6")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "2001:db8::1" {
		t.Errorf("stdout = %q, want the IPv6 answer", got)
	}

	v4 := stubClient(t, stubMethod{method: publicip.HTTP, stub: stub{ip: "192.0.2.5"}})
	err, stdout, _ = runCLI(t, v4, "--ip-version", "4")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "192.0.2.5" {
		t.Errorf("stdout = %q, want 192.0.2.5", got)
	}
}

func TestRunAllWithOneFamilyOnly(t *testing.T) {
	// -a -i 4 must probe IPv4 alone: an IPv6-only stub cannot answer, so nothing is found.
	client := stubClient(t, stubMethod{method: publicip.STUN, stub: stub{family: "6", ip: "2001:db8::2"}})
	err, stdout, _ := runCLI(t, client, "-a", "-i", "4")
	if err == nil || !strings.Contains(err.Error(), "no public IP") {
		t.Fatalf("run() error = %v with stdout %q, want the not-found failure", err, stdout)
	}

	// Asking for that same family does find it.
	err, stdout, _ = runCLI(t, client, "-a", "-i", "6")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got := strings.TrimSpace(stdout); got != "2001:db8::2" {
		t.Errorf("stdout = %q, want 2001:db8::2", got)
	}
}

func TestRunAllVerbosePrintsFailuresAlongsideResults(t *testing.T) {
	// Some probes fail, one answers: the plain output lists the addresses and the
	// failures go to stderr, which is the whole reason -v exists.
	client := stubClient(t,
		stubMethod{method: publicip.STUN, stub: stub{ip: "203.0.113.80"}},
		stubMethod{method: publicip.DNS, stub: stub{err: errors.New("server misbehaving")}},
	)

	err, stdout, stderr := runCLI(t, client, "--all", "--verbose")
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !strings.Contains(stdout, "203.0.113.80") {
		t.Errorf("stdout = %q, want the address that was found", stdout)
	}
	if !strings.Contains(stderr, "server misbehaving") {
		t.Errorf("stderr = %q, want the failed probe reported", stderr)
	}
}
