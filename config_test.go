package publicip

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()

	if c == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
	if c.RequestTimeout != 5*time.Second {
		t.Errorf("RequestTimeout = %v, want 5s", c.RequestTimeout)
	}
	if c.RequestTimeout <= 0 {
		t.Error("RequestTimeout must be positive")
	}
}

func TestDefaultConfigSubsectionsWithDefaults(t *testing.T) {
	c := DefaultConfig()

	if len(c.STUNConfig.Servers) == 0 {
		t.Error("no default STUN servers")
	}
	if len(c.DNSConfig.Servers) == 0 {
		t.Error("no default DNS servers")
	}
	if len(c.HTTPConfig.Endpoints) == 0 {
		t.Error("no default HTTP endpoints")
	}

	// The three sections must be independent copies: mutating one config must not
	// leak into the next client built from DefaultConfig().
	c.STUNConfig.Servers[0] = "127.0.0.1:3478"
	if DefaultConfig().STUNConfig.Servers[0] == "127.0.0.1:3478" {
		t.Error("DefaultConfig() shares its STUN server slice between calls")
	}
}

func TestDefaultSTUNServersFormat(t *testing.T) {
	for _, server := range DefaultSTUNConfig().Servers {
		host, port, found := strings.Cut(server, ":")
		if !found || host == "" || port == "" {
			t.Errorf("STUN server %q is not host:port", server)
			continue
		}
		if !strings.Contains(host, ".") {
			t.Errorf("STUN server %q does not look like a hostname", server)
		}
		if port != "19302" && port != "3478" {
			t.Errorf("STUN server %q uses port %q, want a standard STUN port", server, port)
		}
	}
}

func TestDefaultDNSServersFormat(t *testing.T) {
	// The parser in dns.go splits on ":" and requires exactly two parts, so a
	// default that does not match is a shipped bug.
	for _, server := range DefaultDNSConfig().Servers {
		parts := strings.Split(server, ":")
		if len(parts) != 2 {
			t.Errorf("DNS server %q must be resolver:query-name, got %d parts", server, len(parts))
			continue
		}
		if parts[0] == "" || parts[1] == "" {
			t.Errorf("DNS server %q has an empty resolver or query name", server)
		}
	}
}

func TestDefaultHTTPEndpointsAreHTTPS(t *testing.T) {
	for _, endpoint := range DefaultHTTPConfig().Endpoints {
		u, err := url.Parse(endpoint)
		if err != nil {
			t.Errorf("endpoint %q does not parse: %v", endpoint, err)
			continue
		}
		if u.Scheme != "https" {
			t.Errorf("endpoint %q uses %q, want https", endpoint, u.Scheme)
		}
		if u.Host == "" {
			t.Errorf("endpoint %q has no host", endpoint)
		}
	}
}
