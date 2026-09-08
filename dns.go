package publicip

import (
	"context"
	"fmt"
	"net"
	"time"
)

// DNSServer is one of the DNS services used for discovery: a resolver to ask and the
// query name that answers with the caller's address.
//
// Addr may carry a port ("127.0.0.1:5300"); when it does not, the standard resolver port
// 53 is used. Naming the port is what makes a private or non-standard resolver, and a
// test that stands in for one, possible.
type DNSServer struct {
	// Addr is the resolver to query, with an optional port.
	Addr string
	// QueryName is the record whose answer is the caller's address, such as
	// "myip.opendns.com".
	QueryName string
}

// String renders the server as it appears in failure reports.
func (s DNSServer) String() string {
	if s.Addr == "" && s.QueryName == "" {
		return "<empty DNS server>"
	}
	return s.resolver() + " " + s.QueryName
}

// resolver returns Addr with its port, defaulting to 53 when the caller left it off.
func (s DNSServer) resolver() string {
	if _, _, err := net.SplitHostPort(s.Addr); err == nil {
		return s.Addr
	}
	return net.JoinHostPort(s.Addr, "53")
}

// dnsDiscoverer implements discovery by asking a DNS service what address it sees.
type dnsDiscoverer struct {
	cfg config
}

// newDNSDiscoverer builds a discoverer from the client configuration.
func newDNSDiscoverer(cfg config) *dnsDiscoverer {
	return &dnsDiscoverer{cfg: cfg}
}

// lookup resolves one query name against one resolver over the forced family. It is a
// variable on the discoverer so a test can supply answers without needing the privileges
// a real resolver on port 53 would require.
type lookupFunc func(ctx context.Context, network, resolver, name string) ([]string, error)

// systemLookup asks the Go resolver, bound to a specific address family, of a named
// resolver.
func systemLookup(ctx context.Context, network, resolver, name string) ([]string, error) {
	dialer := &net.Dialer{
		FallbackDelay: -1, // Disable IPv4 fallback when requesting IPv6
	}
	r := &net.Resolver{
		PreferGo: true, // Use Go's built-in DNS resolver
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, resolver)
		},
	}
	return r.LookupHost(ctx, name)
}

// tryQuery asks one DNS service for the address it sees, over the forced family.
func (d *dnsDiscoverer) tryQuery(ctx context.Context, server DNSServer, family string, timeout time.Duration) (net.IP, error) {
	if server.Addr == "" || server.QueryName == "" {
		return nil, fmt.Errorf("invalid DNS server %q: both an address and a query name are required", server)
	}

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := d.cfg.lookup(queryCtx, "udp"+family, server.resolver(), server.QueryName)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs returned from DNS query for %s", server.QueryName)
	}

	ip := net.ParseIP(ips[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid IP received: %s", ips[0])
	}

	// Verify IP version matches the network type
	if mismatch := familyMismatch(ip, family); mismatch != nil {
		return nil, mismatch
	}
	return ip, nil
}

// familyMismatch reports whether an address came back in the family that was asked for.
// Sharing the check keeps the three methods from stating it three different ways.
func familyMismatch(ip net.IP, family string) error {
	isIPv4 := ip.To4() != nil
	if (family == "4" && !isIPv4) || (family == "6" && isIPv4) {
		asked := "6"
		if family == "4" {
			asked = "4"
		}
		got := "6"
		if isIPv4 {
			got = "4"
		}
		return fmt.Errorf("IP version mismatch: got IPv%s when requesting IPv%s", got, asked)
	}
	return nil
}

// Discover implements the Discoverer interface for DNS.
func (d *dnsDiscoverer) Discover(ctx context.Context, version IPVersion) (Result, error) {
	return run(&d.cfg, ctx, DNS, d.cfg.dnsServers, version, d.tryQuery, DNSServer.String)
}
