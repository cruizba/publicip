package publicip

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// maxAddressBodyBytes bounds what an echo service may answer with. An address is at most
// 45 bytes; anything larger is not an address, and reading an unbounded body would let a
// misconfigured or hostile endpoint make a discovery call allocate without limit.
const maxAddressBodyBytes = 128

// httpDiscoverer implements discovery by fetching the address from an HTTP service.
type httpDiscoverer struct {
	cfg config

	// clients holds one client per address family. Building a Transport per request, as
	// v1 did, threw away connection reuse and left the idle connections of every
	// attempt behind; one per family keeps the family forced while the pool is shared.
	clients map[string]*http.Client
}

// newHTTPDiscoverer builds a discoverer from the client configuration.
func newHTTPDiscoverer(cfg config) *httpDiscoverer {
	d := &httpDiscoverer{cfg: cfg, clients: make(map[string]*http.Client, 2)}
	for _, family := range []string{"4", "6"} {
		d.clients[family] = d.clientForFamily(family)
	}
	return d
}

// clientForFamily derives the client for one address family from the configured base.
//
// Forcing the family happens in DialContext rather than DialTLSContext, so net/http
// performs the TLS handshake itself on the connection we dialed: the v1 form called
// tls.DialWithDialer, which uses context.Background() internally and could not be
// cancelled by the caller.
func (d *httpDiscoverer) clientForFamily(family string) *http.Client {
	base := d.cfg.httpClient
	if base == nil {
		base = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	}

	transport, ok := transportFor(base.Transport)
	if !ok {
		// A custom RoundTripper decides its own addressing; respect that rather than
		// quietly overriding it.
		client := *base
		return &client
	}

	dialed := transport.Clone()
	network := "tcp" + family
	dialed.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		return d.cfg.dial(ctx, network, addr)
	}
	dialed.ForceAttemptHTTP2 = true

	client := *base
	client.Transport = dialed
	return &client
}

func transportFor(rt http.RoundTripper) (*http.Transport, bool) {
	switch t := rt.(type) {
	case nil:
		return http.DefaultTransport.(*http.Transport).Clone(), true
	case *http.Transport:
		return t, true
	default:
		return nil, false
	}
}

// tryProtocol fetches the address from one HTTP echo service over the forced family.
func (d *httpDiscoverer) tryProtocol(ctx context.Context, endpoint, family string, timeout time.Duration) (net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// The client is per family, and the context bounds the attempt; the extra timeout
	// only applies to callers who passed a context without a deadline.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := d.clients[family].Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAddressBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if len(body) > maxAddressBodyBytes {
		return nil, fmt.Errorf("response from %s is larger than %d bytes", endpoint, maxAddressBodyBytes)
	}

	ip, err := parseAddressBody(body)
	if err != nil {
		return nil, err
	}

	if mismatch := familyMismatch(ip, family); mismatch != nil {
		return nil, mismatch
	}
	return ip, nil
}

// parseAddressBody turns an echo service's response into an address. It is separate from
// the request so the trimming and rejection rules can be fuzzed directly.
func parseAddressBody(body []byte) (net.IP, error) {
	ipStr := strings.TrimSpace(string(body))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP received: %s", ipStr)
	}
	return ip, nil
}

// Discover implements the Discoverer interface for HTTP.
func (d *httpDiscoverer) Discover(ctx context.Context, version IPVersion) (Result, error) {
	return run(&d.cfg, ctx, HTTP, d.cfg.httpEndpoints, version, d.tryProtocol, identity)
}
