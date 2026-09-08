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

func (f fakeDiscoverer) Discover(_ context.Context, version IPVersion) (net.IP, error) {
	if f.calls != nil {
		*f.calls = append(*f.calls, string(f.name))
	}
	if f.err != nil {
		return nil, f.err
	}
	return net.ParseIP(f.ip), nil
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
		WithDNSServers("198.51.100.1:query"),
		WithHTTPEndpoints("http://203.0.113.9"),
		WithTimeout(2*time.Second),
		WithAttemptTimeout(111*time.Millisecond),
		WithMethods(HTTP, DNS),
	)

	if got := c.config.stunServers; len(got) != 1 || got[0] != "192.0.2.2:3478" {
		t.Errorf("stunServers = %v, want the last option's value", got)
	}
	if got := c.config.dnsServers; len(got) != 1 || got[0] != "198.51.100.1:query" {
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

	ip, err := c.DiscoverWithMethod(context.Background(), HTTP, IPv4Only)
	if err != nil {
		t.Fatalf("DiscoverWithMethod() error = %v", err)
	}
	if got := ip.String(); got != "203.0.113.5" {
		t.Errorf("DiscoverWithMethod() = %s, want 203.0.113.5", got)
	}
}

func TestFallbackOrderIsStunDNSHTTP(t *testing.T) {
	var calls []string
	c := clientWith(map[Method]discoverer{
		STUN: fakeDiscoverer{name: STUN, err: ErrNoIPDiscovered, calls: &calls},
		DNS:  fakeDiscoverer{name: DNS, err: ErrNoIPDiscovered, calls: &calls},
		HTTP: fakeDiscoverer{name: HTTP, ip: "198.51.100.1", calls: &calls},
	})

	ip, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := ip.String(); got != "198.51.100.1" {
		t.Errorf("Discover() = %s, want 198.51.100.1", got)
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

	if _, err := c.DiscoverWithIpVersion(context.Background(), IPv4Only); err != nil {
		t.Fatalf("DiscoverWithIpVersion() error = %v", err)
	}
	if got := strings.Join(calls, ","); got != "stun" {
		t.Errorf("methods tried = %q, want only %q", got, "stun")
	}
}

func TestDiscoverWithIpVersionPassesVersionThrough(t *testing.T) {
	seen := make(chan IPVersion, 1)
	c := clientWith(map[Method]discoverer{
		STUN: versionSpy{seen: seen, ip: "2001:db8::1"},
	})

	if _, err := c.DiscoverWithIpVersion(context.Background(), IPv6Only); err != nil {
		t.Fatalf("DiscoverWithIpVersion() error = %v", err)
	}
	if got := <-seen; got != IPv6Only {
		t.Errorf("discoverer saw version %v, want IPv6Only", got)
	}
}

type versionSpy struct {
	seen chan<- IPVersion
	ip   string
}

func (v versionSpy) Discover(_ context.Context, version IPVersion) (net.IP, error) {
	v.seen <- version
	return net.ParseIP(v.ip), nil
}
