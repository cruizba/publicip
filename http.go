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
	requestTimeout time.Duration
	config         HTTPConfig
}

// newHTTPDiscovererWithConfig creates a new HTTP-based IP discoverer with the provided configuration
func newHTTPDiscovererWithConfig(timeout time.Duration, config HTTPConfig) *httpDiscoverer {
	return &httpDiscoverer{
		requestTimeout: timeout,
		config:         config,
	}
}

// tryProtocol attempts to discover IP using the specified network (tcp4 or tcp6)
func (d *httpDiscoverer) tryProtocol(ctx context.Context, endpoint, network string) (net.IP, error) {
	dialer := &net.Dialer{
		Timeout:       d.requestTimeout,
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
		Timeout: d.requestTimeout,
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
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

// Discover implements the discoverer interface for HTTP
func (d *httpDiscoverer) Discover(ctx context.Context, version IPVersion) (net.IP, error) {
	if version == Any || version == IPv6Only {
		for _, endpoint := range d.config.Endpoints {
			ip, err := d.tryProtocol(ctx, endpoint, "tcp6")
			if err == nil {
				return ip, nil
			}
			logDebug("IPv6 connection failed for %s: %v", endpoint, err)
		}
	}
	if version == Any || version == IPv4Only {
		for _, endpoint := range d.config.Endpoints {
			ip, err := d.tryProtocol(ctx, endpoint, "tcp4")
			if err == nil {
				return ip, nil
			}
			logDebug("IPv4 connection failed for %s: %v", endpoint, err)
		}
	}

	logDebug("All HTTP endpoints failed to discover IP")
	return nil, ErrNoIPDiscovered

}
