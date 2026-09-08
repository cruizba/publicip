package publicip

import (
	"context"
	"net"
)

// IPVersion specifies the IP version to discover.
type IPVersion int

const (
	// Any accepts whichever family answers first: IPv6 is tried before IPv4 for every
	// method, matching the order v1 shipped.
	Any IPVersion = iota
	// IPv4Only returns only IPv4 addresses.
	IPv4Only
	// IPv6Only returns only IPv6 addresses.
	IPv6Only
)

// Method represents the discovery method used to find the public IP.
type Method string

const (
	// STUN asks a STUN server what address it saw the request come from.
	STUN Method = "stun"
	// DNS queries a DNS service that answers with the caller's address.
	DNS Method = "dns"
	// HTTP fetches the address from an HTTP echo service.
	HTTP Method = "http"
)

// discoverer performs discovery with one method. v2 exports an equivalent interface for
// callers that want to add their own method.
type discoverer interface {
	// Discover attempts to find the public IP with this method. Implementations must
	// respect ctx, including its deadline and cancellation.
	Discover(ctx context.Context, version IPVersion) (net.IP, error)
}

// Client discovers public IP addresses over STUN, DNS and HTTP.
//
// A Client is safe for concurrent use: its configuration is fixed at construction and
// each call carries its own state.
type Client struct {
	config      config
	discoverers map[Method]discoverer
}

// New returns a Client configured by the given options, with sensible defaults for
// everything left unset.
func New(opts ...Option) *Client {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return &Client{
		config: cfg,
		discoverers: map[Method]discoverer{
			STUN: newSTUNDiscoverer(cfg),
			DNS:  newDNSDiscoverer(cfg),
			HTTP: newHTTPDiscoverer(cfg),
		},
	}
}

// callContext bounds one discovery call by the client's timeout, if it has one. The
// caller's context always wins: the effective deadline is the earlier of the two.
func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.config.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.config.timeout)
}

// DiscoverWithMethod discovers the public IP using one specific method.
func (c *Client) DiscoverWithMethod(ctx context.Context, method Method, version IPVersion) (net.IP, error) {
	target, ok := c.discoverers[method]
	if !ok {
		c.config.logger.Debug("unsupported method", "method", string(method))
		return nil, ErrUnsupportedMethod
	}

	ctx, cancel := c.callContext(ctx)
	defer cancel()

	ip, err := target.Discover(ctx, version)
	if err != nil {
		c.config.logger.Debug("method failed", "method", string(method), "error", err)
		return nil, err
	}
	return ip, nil
}

// DiscoverWithIpVersion tries every configured method in order for one address family.
func (c *Client) DiscoverWithIpVersion(ctx context.Context, version IPVersion) (net.IP, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()

	for _, method := range c.config.methods {
		if err := ctx.Err(); err != nil {
			c.config.logger.Debug("no budget left for further methods", "error", err)
			break
		}

		target, ok := c.discoverers[method]
		if !ok {
			c.config.logger.Debug("skipping unconfigured method", "method", string(method))
			continue
		}

		ip, err := target.Discover(ctx, version)
		if err == nil {
			return ip, nil
		}
		c.config.logger.Debug("method failed", "method", string(method), "error", err)
	}

	c.config.logger.Debug("all discovery methods failed")
	return nil, ErrNoIPDiscovered
}

// Discover tries every configured method, IPv6 before IPv4, and returns the first
// address found.
func (c *Client) Discover(ctx context.Context) (net.IP, error) {
	return c.DiscoverWithIpVersion(ctx, Any)
}
