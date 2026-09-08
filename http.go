package publicip

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// httpDiscoverer implements IP discovery using HTTP requests
type httpDiscoverer struct {
	cfg config
}

// newHTTPDiscoverer builds a discoverer for one method from the client configuration.
func newHTTPDiscoverer(cfg config) *httpDiscoverer {
	return &httpDiscoverer{cfg: cfg}
}

// tryProtocol fetches the address from one HTTP echo service over the forced family.
func (d *httpDiscoverer) tryProtocol(ctx context.Context, target attempt, timeout time.Duration) (net.IP, error) {
	network := "tcp" + target.family

	dialer := &net.Dialer{
		Timeout:       timeout,
		FallbackDelay: -1, // Disable IPv4 fallback when requesting IPv6
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			// Force specific network type (tcp4 or tcp6)
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return tls.DialWithDialer(dialer, network, addr, nil)
			},
		},
		Timeout: timeout,
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.target, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse IP from response
	ipStr := strings.TrimSpace(string(body))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP received: %s", ipStr)
	}

	// Verify IP version matches the network type
	isIPv4 := ip.To4() != nil
	if (network == "tcp4" && !isIPv4) || (network == "tcp6" && isIPv4) {
		return nil, fmt.Errorf("IP version mismatch: got IPv%d when requesting IPv%d",
			map[bool]int{true: 4, false: 6}[isIPv4],
			map[string]int{"tcp4": 4, "tcp6": 6}[network])
	}

	return ip, nil
}

// Discover implements the Discoverer interface for HTTP.
func (d *httpDiscoverer) Discover(ctx context.Context, version IPVersion) (Result, error) {
	return d.cfg.run(ctx, HTTP, d.cfg.httpEndpoints, version, d.tryProtocol)
}
