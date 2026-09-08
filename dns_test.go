package publicip

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The happy path of a DNS discovery needs a resolver we control listening on the
// port the config implies, and v1 hardcodes ":53" when it dials:
//
//	dialer.DialContext(ctx, network, dnsServer+":53")
//
// Binding port 53 requires privileges that CI does not have either, so the
// round-trip tests below only cover the failure paths that are reachable without
// them. Giving DNSConfig an explicit address (including a port) is part of the v2
// redesign, at which point the answering-server tests land here too.

func dnsClient(servers []string, timeout time.Duration) *dnsDiscoverer {
	return newDNSDiscovererWithConfig(timeout, DNSConfig{Servers: servers})
}

func TestDNSRejectsMalformedServerEntries(t *testing.T) {
	tests := []struct {
		name   string
		server string
	}{
		{"no separator", "127.0.0.1"},
		{"more than one separator", "127.0.0.1:my.query:53"}, // hermetic:allow
		{"empty", ""},
		{"trailing separator", "127.0.0.1:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := dnsClient([]string{tt.server}, time.Second)
			_, err := d.Discover(context.Background(), IPv4Only)
			if err != ErrNoIPDiscovered {
				t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
			}
		})
	}
}

func TestDNSQueryReportsUnreachableServer(t *testing.T) {
	// Nothing listens on this UDP port, so the resolver fails fast and the
	// discoverer keeps walking the list before giving up.
	d := dnsClient([]string{"127.0.0.1:nothing", "127.0.0.2:nothing"}, 500*time.Millisecond)

	_, err := d.Discover(context.Background(), IPv4Only)
	if err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
	}
}

// TestDNSDefaultsAreUsable checks the shipped server list keeps the format the
// parser expects, without touching the network.
func TestDNSDefaultsAreUsable(t *testing.T) {
	for _, server := range dnsTestServers() {
		if got := strings.Count(server, ":"); got != 1 {
			t.Errorf("default DNS server %q has %d separators, want exactly 1", server, got)
		}
	}
}

// dnsTestServers returns the shipped default list for shape checks. It is kept in
// its own function so the only place that touches real hostnames is this offline
// format check, which never dials.
func dnsTestServers() []string {
	return DefaultDNSConfig().Servers
}
