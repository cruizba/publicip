package publicip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeDiscoverer records calls and returns a canned answer, so the fallback logic
// can be tested without touching the network.
type fakeDiscoverer struct {
	name  Method
	ip    string
	err   error
	calls *[]string
}

func (f fakeDiscoverer) Discover(_ context.Context, version IPVersion) (Result, error) {
	if f.calls != nil {
		*f.calls = append(*f.calls, string(f.name))
	}
	if f.err != nil {
		return Result{}, f.err
	}
	ip := net.ParseIP(f.ip)
	return Result{IP: ip, Method: f.name, Version: versionOf(ip)}, nil
}

// clientWith swaps in the given discoverers, leaving the rest of the client as-is.
func clientWith(discoverers map[Method]discoverer) *Client {
	c := New()
	c.discoverers = discoverers
	return c
}

func TestNewUsesDefaults(t *testing.T) {
	c := New()

	if c.config.attemptTimeout != defaultAttemptTimeout {
		t.Errorf("attemptTimeout = %v, want the default %v", c.config.attemptTimeout, defaultAttemptTimeout)
	}
	if c.config.timeout != 0 {
		t.Errorf("timeout = %v, want 0: the caller's context is the budget by default", c.config.timeout)
	}
	for _, m := range []Method{STUN, DNS, HTTP} {
		if _, ok := c.discoverers[m]; !ok {
			t.Errorf("client has no discoverer for method %q", m)
		}
	}
	if len(c.discoverers) != 3 {
		t.Errorf("client has %d discoverers, want 3", len(c.discoverers))
	}
}

func TestNewAppliesOptionsInOrder(t *testing.T) {
	c := New(
		WithSTUNServers("192.0.2.1:3478"),
		WithSTUNServers("192.0.2.2:3478"), // a later option wins
		WithDNSServers(DNSServer{Addr: "198.51.100.1", QueryName: dnsQueryName}),
		WithHTTPEndpoints("http://203.0.113.9"),
		WithTimeout(2*time.Second),
		WithAttemptTimeout(111*time.Millisecond),
		WithMethods(HTTP, DNS),
	)

	if got := c.config.stunServers; len(got) != 1 || got[0] != "192.0.2.2:3478" {
		t.Errorf("stunServers = %v, want the last option's value", got)
	}
	if got := c.config.dnsServers; len(got) != 1 || got[0] != (DNSServer{Addr: "198.51.100.1", QueryName: dnsQueryName}) {
		t.Errorf("dnsServers = %v, want the configured single server", got)
	}
	if got := c.config.httpEndpoints; len(got) != 1 || got[0] != "http://203.0.113.9" {
		t.Errorf("httpEndpoints = %v, want the configured endpoint", got)
	}
	if c.config.timeout != 2*time.Second {
		t.Errorf("timeout = %v, want 2s", c.config.timeout)
	}
	if c.config.attemptTimeout != 111*time.Millisecond {
		t.Errorf("attemptTimeout = %v, want 111ms", c.config.attemptTimeout)
	}
	if got := fmt.Sprint(c.config.methods); got != "[http dns]" {
		t.Errorf("methods = %s, want the order the caller asked for", got)
	}
}

func TestNewIgnoresNonsenseOptions(t *testing.T) {
	// A nil Option must not panic, and zero/negative durations must not disarm the
	// defaults: an unbounded attempt would let one black-holed server hang the call.
	c := New(nil, WithTimeout(-time.Second), WithAttemptTimeout(0), WithMethods(), WithHTTPClient(nil))

	if c.config.timeout != 0 {
		t.Errorf("timeout = %v, want 0 (unset means the context decides)", c.config.timeout)
	}
	if c.config.attemptTimeout != defaultAttemptTimeout {
		t.Errorf("attemptTimeout = %v, want the default %v", c.config.attemptTimeout, defaultAttemptTimeout)
	}
	if got := fmt.Sprint(c.config.methods); got != "[stun dns http]" {
		t.Errorf("methods = %s, want the default order preserved", got)
	}
	if c.config.httpClient != nil {
		t.Error("httpClient = non-nil, want nil so one is built on demand")
	}
}

func TestDiscoverWithMethodUnsupported(t *testing.T) {
	// Built through the sandbox even though this path returns before dialing: the rule
	// "any test calling Discover* uses newTestClient" is worth more than the exception.
	c := newTestClient(t)

	_, err := c.DiscoverWithMethod(context.Background(), Method("carrier-pigeon"), Any)
	if err != ErrUnsupportedMethod {
		t.Fatalf("DiscoverWithMethod() error = %v, want ErrUnsupportedMethod", err)
	}
	if err.Error() != "unsupported discovery method" {
		t.Errorf("error text = %q, want %q", err, "unsupported discovery method")
	}
}

func TestDiscoverWithMethodPropagatesDiscoveryError(t *testing.T) {
	boom := errors.New("backend exploded")
	c := clientWith(map[Method]discoverer{
		STUN: fakeDiscoverer{name: STUN, err: boom},
	})

	_, err := c.DiscoverWithMethod(context.Background(), STUN, IPv4Only)
	if err != boom {
		t.Fatalf("DiscoverWithMethod() error = %v, want the discoverer's own error %v", err, boom)
	}
}

func TestDiscoverWithMethodReturnsIP(t *testing.T) {
	c := clientWith(map[Method]discoverer{
		HTTP: fakeDiscoverer{name: HTTP, ip: "203.0.113.5"},
	})

	res, err := c.DiscoverWithMethod(context.Background(), HTTP, IPv4Only)
	if err != nil {
		t.Fatalf("DiscoverWithMethod() error = %v", err)
	}
	if got := res.IP.String(); got != "203.0.113.5" {
		t.Errorf("DiscoverWithMethod() = %v, want 203.0.113.5", got)
	}
}

func TestFallbackOrderIsStunDNSHTTP(t *testing.T) {
	var calls []string
	c := clientWith(map[Method]discoverer{
		STUN: fakeDiscoverer{name: STUN, err: ErrNotFound, calls: &calls},
		DNS:  fakeDiscoverer{name: DNS, err: ErrNotFound, calls: &calls},
		HTTP: fakeDiscoverer{name: HTTP, ip: "198.51.100.1", calls: &calls},
	})

	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := res.IP.String(); got != "198.51.100.1" {
		t.Errorf("Discover() = %v, want 198.51.100.1", got)
	}
	if got, want := strings.Join(calls, ","), "stun,dns,http"; got != want {
		t.Errorf("methods tried in order %q, want %q", got, want)
	}
}

func TestFallbackStopsAtFirstSuccess(t *testing.T) {
	var calls []string
	c := clientWith(map[Method]discoverer{
		STUN: fakeDiscoverer{name: STUN, ip: "203.0.113.1", calls: &calls},
		DNS:  fakeDiscoverer{name: DNS, ip: "203.0.113.2", calls: &calls},
		HTTP: fakeDiscoverer{name: HTTP, ip: "203.0.113.3", calls: &calls},
	})

	if _, err := c.DiscoverWithIPVersion(context.Background(), IPv4Only); err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if got := strings.Join(calls, ","); got != "stun" {
		t.Errorf("methods tried = %q, want only %q", got, "stun")
	}
}

func TestDiscoverWithIPVersionPassesVersionThrough(t *testing.T) {
	seen := make(chan IPVersion, 1)
	c := clientWith(map[Method]discoverer{
		STUN: versionSpy{seen: seen, ip: "2001:db8::1"},
	})

	if _, err := c.DiscoverWithIPVersion(context.Background(), IPv6Only); err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if got := <-seen; got != IPv6Only {
		t.Errorf("discoverer saw version %v, want IPv6Only", got)
	}
}

type versionSpy struct {
	seen chan<- IPVersion
	ip   string
}

func (v versionSpy) Discover(_ context.Context, version IPVersion) (Result, error) {
	v.seen <- version
	ip := net.ParseIP(v.ip)
	return Result{IP: ip, Version: versionOf(ip)}, nil
}

// --- user-supplied discoverers --------------------------------------------

const upnp Method = "upnp"

// stubDiscoverer implements the exported Discoverer contract.
type stubDiscoverer struct {
	method Method
	ip     string
	err    error
	calls  *[]Method
}

func (s stubDiscoverer) Discover(_ context.Context, _ IPVersion) (Result, error) {
	if s.calls != nil {
		*s.calls = append(*s.calls, s.method)
	}
	if s.err != nil {
		return Result{}, s.err
	}
	ip := net.ParseIP(s.ip)
	return Result{IP: ip, Method: s.method, Version: versionOf(ip)}, nil
}

func TestWithMethodRegistersACustomSource(t *testing.T) {
	var calls []Method
	c := newTestClient(t,
		WithMethod(upnp, stubDiscoverer{method: upnp, ip: "192.0.2.7", calls: &calls}),
		WithMethods(upnp),
	)

	res, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := res.IP.String(); got != "192.0.2.7" {
		t.Errorf("Discover() = %v, want 192.0.2.7", got)
	}
	if res.Method != upnp {
		t.Errorf("Result.Method = %q, want %q", res.Method, upnp)
	}
	if got := fmt.Sprint(calls); got != "[upnp]" {
		t.Errorf("custom discoverer called %v, want exactly once", got)
	}
}

func TestWithMethodReplacesTheBuiltIn(t *testing.T) {
	// Registering under DNS must shadow the built-in DNS, not run beside it, or a
	// caller with their own resolver would still see queries leave for the defaults.
	var calls []Method
	c := newTestClient(t,
		WithMethod(DNS, stubDiscoverer{method: DNS, ip: "198.51.100.24", calls: &calls}),
		WithMethods(DNS),
		WithDNSServers(), // built-in targets emptied: a leak here would be a dial to nothing
	)

	res, err := c.DiscoverWithIPVersion(context.Background(), IPv4Only)
	if err != nil {
		t.Fatalf("DiscoverWithIPVersion() error = %v", err)
	}
	if res.IP.String() != "198.51.100.24" {
		t.Errorf("DiscoverWithIPVersion() = %v, want the replacement's answer", res.IP)
	}
	if got := fmt.Sprint(calls); got != "[dns]" {
		t.Errorf("calls = %s, want the replacement to be the only DNS discoverer used", got)
	}
}

func TestWithMethodIgnoresEmptyNameAndNilDiscoverer(t *testing.T) {
	c := newTestClient(t, WithMethod("", stubDiscoverer{}), WithMethod(upnp, nil))
	if _, ok := c.discoverers[""]; ok {
		t.Error("an empty method name was registered")
	}
	if d, ok := c.discoverers[upnp]; ok && d == nil {
		t.Error("a nil discoverer was registered, which would panic on use")
	}
	if len(c.discoverers) != 3 {
		t.Errorf("client has %d discoverers, want the 3 built-ins untouched", len(c.discoverers))
	}
}

func TestCustomDiscovererFailureIsAggregated(t *testing.T) {
	boom := errors.New("no lease found")
	var calls []Method
	c := newTestClient(t,
		WithMethod(upnp, stubDiscoverer{method: upnp, err: boom, calls: &calls}),
		WithSTUNServers("127.0.0.1:1"),
		WithMethods(upnp, STUN),
	)

	_, err := c.Discover(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want it to match ErrNotFound", err)
	}
	// The custom discoverer returned a foreign error; it must still be reachable rather
	// than swallowed by the aggregation.
	if !errors.Is(err, boom) {
		t.Error("the custom discoverer's error was lost from the aggregated failure list")
	}
	var de *DiscoveryError
	if !errors.As(err, &de) {
		t.Fatal("want a *DiscoveryError")
	}
	if len(de.Failures()) < 2 {
		t.Errorf("Failures() = %d entries, want one for the custom source and one for STUN", len(de.Failures()))
	}
	if got := fmt.Sprint(calls); got != "[upnp]" {
		t.Errorf("calls = %s, want the custom source tried once", got)
	}
}

func TestUnsupportedMethodErrorOnCustomNameIsStillReachable(t *testing.T) {
	// Registering a discoverer but leaving it out of WithMethods means it is never tried;
	// asking for it explicitly must work, because DiscoverWithMethod ignores the order.
	c := newTestClient(t, WithMethod(upnp, stubDiscoverer{method: upnp, ip: "203.0.113.77"}))
	res, err := c.DiscoverWithMethod(context.Background(), upnp, IPv4Only)
	if err != nil {
		t.Fatalf("DiscoverWithMethod() error = %v", err)
	}
	if res.IP.String() != "203.0.113.77" {
		t.Errorf("DiscoverWithMethod() = %v, want 203.0.113.77", res.IP)
	}
}

func TestMethodsWithoutADiscovererAreSkippedNotFatal(t *testing.T) {
	// WithMethods accepts any Method, including one nobody registered: the call must
	// report "nothing found" rather than panic on a nil map entry.
	c := newTestClient(t, WithMethods(Method("carrier-pigeon"), Method("gps")))

	_, err := c.Discover(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Discover() error = %v, want it to match ErrNotFound", err)
	}

	var de *DiscoveryError
	if !errors.As(err, &de) {
		t.Fatal("want a *DiscoveryError")
	}
	if len(de.Failures()) != 0 {
		t.Errorf("Failures() = %d, want 0: nothing was attempted", len(de.Failures()))
	}
}

func TestCustomDiscovererCanReportFailuresInDetail(t *testing.T) {
	// NewDiscoveryError exists so a user-supplied source fails in the same shape as a
	// built-in one: the aggregated report keeps its per-target detail across the
	// boundary.
	detail := NewDiscoveryError([]Failure{
		{Method: upnp, Target: "http://127.0.0.1:1/upnp", Family: "4", Err: errors.New("404 not found")},
		{Method: upnp, Target: "http://127.0.0.1:2/upnp", Family: "4", Err: errors.New("connection refused")},
	}, false)

	var calls []Method
	c := newTestClient(t,
		WithMethod(upnp, failingDiscoverer{method: upnp, err: detail, calls: &calls}),
		WithMethods(upnp),
	)

	_, err := c.Discover(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Discover() error = %v, want ErrNotFound", err)
	}
	var de *DiscoveryError
	if !errors.As(err, &de) {
		t.Fatal("want a *DiscoveryError")
	}
	if len(de.Failures()) != 2 {
		t.Errorf("Failures() = %d, want the two targets reported by the custom discoverer", len(de.Failures()))
	}
	for _, f := range de.Failures() {
		if f.Method != upnp {
			t.Errorf("failure method = %q, want %q", f.Method, upnp)
		}
	}
}

type failingDiscoverer struct {
	method Method
	err    error
	calls  *[]Method
}

func (f failingDiscoverer) Discover(_ context.Context, _ IPVersion) (Result, error) {
	if f.calls != nil {
		*f.calls = append(*f.calls, f.method)
	}
	return Result{}, f.err
}
