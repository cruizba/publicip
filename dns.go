package publicip

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// dnsDiscoverer implements IP discovery using DNS queries
type dnsDiscoverer struct {
	cfg config
}

// newDNSDiscoverer builds a discoverer for one method from the client configuration.
func newDNSDiscoverer(cfg config) *dnsDiscoverer {
	return &dnsDiscoverer{cfg: cfg}
}

// tryQuery asks one DNS service for the address it sees, over the forced family.
func (d *dnsDiscoverer) tryQuery(ctx context.Context, target attempt, timeout time.Duration) (net.IP, error) {
	network := "udp" + target.family

	// Split server:domain format
	parts := strings.Split(target.target, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid DNS server format (expected server:domain): %s", target.target)
	}
	dnsServer, domain := parts[0], parts[1]

	// Create a DNS resolver with specific network type
	dialer := &net.Dialer{
		Timeout:       timeout,
		FallbackDelay: -1, // Disable IPv4 fallback when requesting IPv6
	}

	resolver := &net.Resolver{
		PreferGo: true, // Use Go's built-in DNS resolver
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// Force specific network type (udp4 or udp6)
			return dialer.DialContext(ctx, network, dnsServer+":53")
		},
	}

	// Make the DNS query
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs returned from DNS query")
	}

	// Parse the first IP address
	ip := net.ParseIP(ips[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid IP received: %s", ips[0])
	}

	// Verify IP version matches the network type
	isIPv4 := ip.To4() != nil
	if (network == "udp4" && !isIPv4) || (network == "udp6" && isIPv4) {
		return nil, fmt.Errorf("IP version mismatch: got IPv%d when requesting IPv%d",
			map[bool]int{true: 4, false: 6}[isIPv4],
			map[string]int{"udp4": 4, "udp6": 6}[network])
	}

	return ip, nil
}

// Discover implements the Discoverer interface for DNS.
func (d *dnsDiscoverer) Discover(ctx context.Context, version IPVersion) (Result, error) {
	return d.cfg.run(ctx, DNS, d.cfg.dnsServers, version, d.tryQuery)
}
