package publicip

import (
	"context"
	"errors"
	"net"
	"strings"
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

// Result is a discovered public address together with how it was obtained.
type Result struct {
	// IP is the discovered address.
	IP net.IP
	// Method is the discovery method that produced it.
	Method Method
	// Version is the family of IP: IPv4Only or IPv6Only. It is derived from the
	// address, never from what the caller asked for, so a Result can be trusted even
	// when a discoverer is supplied by the caller.
	Version IPVersion
}

// String renders the address with its provenance, for logs and terminal output. Use
// Result.IP.String() when only the address should appear.
func (r Result) String() string {
	if r.IP == nil {
		return "<empty result>"
	}
	family := "ipv6"
	if r.Version == IPv4Only {
		family = "ipv4"
	}
	method := string(r.Method)
	if method == "" {
		method = "unknown"
	}
	var b strings.Builder
	b.WriteString(r.IP.String())
	b.WriteString(" (")
	b.WriteString(method)
	b.WriteByte('/')
	b.WriteString(family)
	b.WriteByte(')')
	return b.String()
}

// Discoverer finds the public address with one method. Implement it to add a source the
// package does not ship - a local router API, a private echo service - or to replace one
// it does.
//
// Contract for implementations:
//   - respect ctx: honour its deadline and cancellation rather than running to completion
//   - return a Result whose IP is non-nil, and whose Method and Version describe the
//     address actually found (the client trusts those fields, not what was requested)
//   - on failure return an error that wraps ErrNotFound, ideally a *DiscoveryError built
//     with NewDiscoveryError, so callers can inspect which targets failed
//   - be safe for concurrent use: one Client may call Discover from several goroutines
type Discoverer interface {
	Discover(ctx context.Context, version IPVersion) (Result, error)
}

// discoverer is the internal alias; keeping one definition means a user-supplied
// Discoverer and a built-in one are checked identically.
type discoverer = Discoverer

// NewDiscoveryError builds the error type this package returns for a failed search. It
// is exported so a custom Discoverer can report failures in the same shape as the
// built-in methods.
func NewDiscoveryError(failures []Failure, timedOut bool) *DiscoveryError {
	return &DiscoveryError{failures: failures, timedOut: timedOut}
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

	c := &Client{
		config: cfg,
		discoverers: map[Method]discoverer{
			STUN: newSTUNDiscoverer(cfg),
			DNS:  newDNSDiscoverer(cfg),
			HTTP: newHTTPDiscoverer(cfg),
		},
	}

	// Custom discoverers are applied last, so WithMethod(DNS, ...) replaces the built-in
	// DNS rather than sitting beside it.
	for name, d := range cfg.custom {
		c.discoverers[name] = d
	}
	return c
}

// callContext bounds one discovery call by the client's timeout, if it has one. The
// caller's context always wins: the effective deadline is the earlier of the two.
func (c *Client) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.config.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.config.timeout)
}

// DiscoverWithMethod discovers the public address using one specific method.
//
// The returned error is a *DiscoveryError listing what each target answered, or
// ErrUnsupportedMethod when the client has no discoverer for method.
func (c *Client) DiscoverWithMethod(ctx context.Context, method Method, version IPVersion) (Result, error) {
	target, ok := c.discoverers[method]
	if !ok {
		c.config.logger.Debug("unsupported method", "method", string(method))
		return Result{}, ErrUnsupportedMethod
	}

	ctx, cancel := c.callContext(ctx)
	defer cancel()
	return c.invoke(ctx, target, method, version)
}

// invoke runs one discoverer and enforces the family the caller asked for. Built-in
// discoverers already check this per attempt; the check belongs here too because a
// Discoverer supplied through WithMethod is not required to, and a caller of
// DiscoverWithIPVersion(IPv6Only) must never be handed an IPv4 address.
func (c *Client) invoke(ctx context.Context, target discoverer, method Method, version IPVersion) (Result, error) {
	result, err := target.Discover(ctx, version)
	if err != nil {
		c.config.logger.Debug("method failed", "method", string(method), "error", err)
		return Result{}, err
	}

	if version != Any {
		if mismatch := familyMismatch(result.IP, familyOf(version)); mismatch != nil {
			c.config.logger.Debug("method returned the wrong family", "method", string(method), "ip", result.IP.String())
			return Result{}, discoveryError(ctx, []Failure{{
				Method: method, Target: "result", Family: familyOf(version), Err: mismatch,
			}})
		}
	}

	c.config.logger.Debug("address discovered", "method", string(method), "ip", result.IP.String())
	return result, nil
}

// DiscoverWithIPVersion tries every configured method in order, for one address family.
func (c *Client) DiscoverWithIPVersion(ctx context.Context, version IPVersion) (Result, error) {
	ctx, cancel := c.callContext(ctx)
	defer cancel()

	var failures []Failure
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

		result, err := c.invoke(ctx, target, method, version)
		if err == nil {
			return result, nil
		}
		failures = append(failures, failuresOf(err)...)
	}

	c.config.logger.Debug("all discovery methods failed", "attempts", len(failures))
	return Result{}, discoveryError(ctx, failures)
}

// Discover tries every configured method, IPv6 before IPv4, and returns the first
// address found.
func (c *Client) Discover(ctx context.Context) (Result, error) {
	return c.DiscoverWithIPVersion(ctx, Any)
}

// failuresOf extracts the per-target failures from a discoverer's error so a multi-method
// run can report one flat list. A foreign error (a caller-supplied discoverer that
// returns something else) is recorded as a single anonymous failure.
func failuresOf(err error) []Failure {
	var de *DiscoveryError
	if errors.As(err, &de) {
		return de.failures
	}
	return []Failure{{Err: err}}
}

// versionOf derives the IPVersion of an address, so Result.Version describes what was
// found rather than what was asked for.
func versionOf(ip net.IP) IPVersion {
	if ip.To4() != nil {
		return IPv4Only
	}
	return IPv6Only
}
