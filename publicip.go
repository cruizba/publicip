package publicip

import (
	"context"
	"net"
)

// IPVersion specifies the IP version to discover
type IPVersion int

const (
	// Any returns either IPv4 or IPv6
	Any IPVersion = iota
	// IPv4Only returns only IPv4 addresses
	IPv4Only
	// IPv6Only returns only IPv6 addresses
	IPv6Only
)

// Method represents the method used to discover the public IP
type Method string

const (
	// STUN uses STUN protocol to discover public IP
	STUN Method = "stun"
	// DNS uses DNS queries to discover public IP
	DNS Method = "dns"
	// HTTP uses HTTP requests to discover public IP
	HTTP Method = "http"
)

// discoverer interface defines the contract for IP discovery implementations
type discoverer interface {
	// Discover attempts to find the public IP using the specific method
	Discover(ctx context.Context, version IPVersion) (net.IP, error)
}

// Client represents the main public IP discovery client
type Client struct {
	config      *Config
	discoverers map[Method]discoverer
}

// NewClient creates a new public IP discovery client with default configuration
func NewClient() *Client {
	return NewClientWithConfig(DefaultConfig())
}

// NewClientWithConfig creates a new public IP discovery client with the provided configuration
func NewClientWithConfig(config *Config) *Client {
	if config == nil {
		config = DefaultConfig()
	}
	return &Client{
		config: config,
		discoverers: map[Method]discoverer{
			STUN: newSTUNDiscovererWithConfig(config.RequestTimeout, config.STUNConfig),
			DNS:  newDNSDiscovererWithConfig(config.RequestTimeout, config.DNSConfig),
			HTTP: newHTTPDiscovererWithConfig(config.RequestTimeout, config.HTTPConfig),
		},
	}
}

// DiscoverWithMethod discovers public IP using a specific method
func (c *Client) DiscoverWithMethod(ctx context.Context, method Method, version IPVersion) (net.IP, error) {
	discoverer, ok := c.discoverers[method]
	if !ok {
		logDebug("Error: Unsupported method %s", method)
		return nil, ErrUnsupportedMethod
	}
	ip, err := discoverer.Discover(ctx, version)
	if err != nil {
		logDebug("Error: Method %s failed: %v", method, err)
		return nil, err
	}
	return ip, nil
}

// DiscoverWithIpVersion tries all available methods in order until it finds a public IP
func (c *Client) DiscoverWithIpVersion(ctx context.Context, version IPVersion) (net.IP, error) {
	methods := []Method{STUN, DNS, HTTP}

	for _, method := range methods {
		ip, err := c.DiscoverWithMethod(ctx, method, version)
		if err == nil {
			return ip, nil
		}
	}

	logDebug("Error: All discovery methods failed")
	return nil, ErrNoIPDiscovered
}

// Discover tries any version IP using all available methods in order until it finds a public IP
func (c *Client) Discover(ctx context.Context) (net.IP, error) {
	return c.DiscoverWithIpVersion(ctx, Any)
}
