package publicip

import (
	"io"
	"testing"
	"time"
)

// newTestClient builds a Client whose three target lists point at closed loopback
// ports. It exists because the shipped defaults are real public services: a test that
// calls New() and then Discover() will reach the internet even though it contains no
// hostname literal, which is the leak class the static fixture scan cannot see. Every
// test that performs discovery goes through here.
func newTestClient(t *testing.T, opts ...Option) *Client {
	t.Helper()

	sandbox := []Option{
		WithSTUNServers("127.0.0.1:1"),
		WithDNSServers(DNSServer{Addr: "127.0.0.1:1", QueryName: dnsQueryName}),
		WithHTTPEndpoints("http://127.0.0.1:1"),
	}
	return New(append(sandbox, opts...)...)
}

// testConfig applies options onto the package defaults, the same way New does, so a
// test can describe only what it cares about.
func testConfig(opts ...Option) config {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// attemptTimeout is the per-attempt ceiling a test's discoverer should use.
func attemptTimeout(d time.Duration) Option { return WithAttemptTimeout(d) }

// dnsQueryName is the record a test asks the fake resolver about. A single label on
// purpose: the hermetic guard flags dotted names, and these fixtures are never resolved.
const dnsQueryName = "myaddr"

// withLookup installs a stub resolver transport. It is test-only: the seam exists in the
// config so the DNS happy path is reachable, but exposing it publicly would make callers
// responsible for a detail they should not have to think about.
func withLookup(fn lookupFunc) Option {
	return func(c *config) { c.lookup = fn }
}

// withRand installs an entropy source. Test-only for the same reason as withLookup.
func withRand(r io.Reader) Option {
	return func(c *config) { c.rand = r }
}

// withDial installs a fake transport for the STUN and HTTP dials.
func withDial(fn dialFunc) Option {
	return func(c *config) { c.dial = fn }
}
