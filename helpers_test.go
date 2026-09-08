package publicip

import (
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
		WithDNSServers("127.0.0.1:query"),
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
