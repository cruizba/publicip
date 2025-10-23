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
	requestTimeout time.Duration
	config         DNSConfig
}

// newDNSDiscovererWithConfig creates a new DNS-based IP discoverer with the provided configuration
func newDNSDiscovererWithConfig(timeout time.Duration, config DNSConfig) *dnsDiscoverer {
	return &dnsDiscoverer{
		requestTimeout: timeout,
		config:         config,
	}
}

// tryQuery attempts to discover IP using the specified DNS server and network type
func (d *dnsDiscoverer) tryQuery(ctx context.Context, server, network string) (net.IP, error) {
	// Split server:domain format
	parts := strings.Split(server, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid DNS server format (expected server:domain): %s", server)
	}
	dnsServer, domain := parts[0], parts[1]

	// Create a DNS resolver with specific network type
	dialer := &net.Dialer{
		Timeout:       d.requestTimeout,
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

// Discover implements the discoverer interface for DNS
func (d *dnsDiscoverer) Discover(ctx context.Context, version IPVersion) (net.IP, error) {
	for _, server := range d.config.Servers {
		// Try IPv6 first if version is Any or IPv6Only
		if version == Any || version == IPv6Only {
			ip, err := d.tryQuery(ctx, server, "udp6")
			if err == nil {
				return ip, nil
			}
			if version == IPv6Only {
				logDebug("IPv6 DNS query failed for %s: %v", server, err)
				continue
			}
		}

		// Try IPv4 if version is Any or IPv4Only
		if version == Any || version == IPv4Only {
			ip, err := d.tryQuery(ctx, server, "udp4")
			if err == nil {
				return ip, nil
			}
			logDebug("IPv4 DNS query failed for %s: %v", server, err)
		}
	}

	logDebug("All DNS servers failed to discover IP")
	return nil, ErrNoIPDiscovered
}
