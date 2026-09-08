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

// tryQuery attempts to discover IP using the specified DNS server and network type
func (d *dnsDiscoverer) tryQuery(ctx context.Context, server, network string, timeout time.Duration) (net.IP, error) {
	// Split server:domain format
	parts := strings.Split(server, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid DNS server format (expected server:domain): %s", server)
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

// Discover implements the discoverer interface for DNS
func (d *dnsDiscoverer) Discover(ctx context.Context, version IPVersion) (net.IP, error) {
	plan := attemptPlan(d.cfg.dnsServers, version)
	for i, server := range plan {
		timeout, ok := attemptBudget(ctx, d.cfg.attemptTimeout, len(plan)-i)
		if !ok {
			d.cfg.logger.Debug("aborting DNS: no time budget left", "server", server.target)
			return nil, ErrNoIPDiscovered
		}
		ip, err := d.tryQuery(ctx, server.target, "udp"+server.family, timeout)
		if err == nil {
			return ip, nil
		}
		d.cfg.logger.Debug("DNS attempt failed", "family", server.family, "server", server.target, "error", err)
	}

	d.cfg.logger.Debug("all DNS servers failed")
	return nil, ErrNoIPDiscovered
}
