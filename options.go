package publicip

import (
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// defaultEntropy is the source of STUN transaction ids. It is a variable so a test can
// substitute a reader that fails, which is the only way to reach the error branch in
// buildBindingRequest.
var defaultEntropy io.Reader = rand.Reader

// defaultAttemptTimeout bounds a single network attempt when the caller supplied neither
// a per-attempt ceiling nor a context deadline, so that a server that swallows packets
// cannot block a discovery call indefinitely.
const defaultAttemptTimeout = 5 * time.Second

// config holds everything a client needs. It is deliberately unexported: callers
// describe it with Options, which lets a new knob be added without breaking anyone and
// without a exported struct whose zero value means something different from its
// documented default.
type config struct {
	timeout        time.Duration // total budget one Discover call may spend; 0 = no extra bound
	attemptTimeout time.Duration // ceiling for a single network attempt
	stunServers    []string
	dnsServers     []DNSServer
	httpEndpoints  []string
	httpClient     *http.Client
	logger         *slog.Logger
	methods        []Method
	custom         map[Method]Discoverer

	// lookup, dial and rand are seams for tests: a resolver on port 53, a connection that
	// refuses mid-handshake and a failure inside crypto/rand are all unreachable without
	// them. They are unexported, so they add nothing to the public API.
	lookup lookupFunc
	dial   dialFunc
	rand   io.Reader
}

// defaultConfig is the shape a New() client gets with no options.
//
// Timeout is zero on purpose. A library that imposes its own deadline fights the
// caller's context, and the CLI's -t flag would silently stop mattering past it. The
// context passed to each Discover method is the budget; WithTimeout exists for callers
// who want to state it on the client instead.
func defaultConfig() config {
	return config{
		stunServers:    append([]string(nil), defaultSTUNServers...),
		dnsServers:     append([]DNSServer(nil), defaultDNSServers...),
		httpEndpoints:  append([]string(nil), defaultHTTPEndpoints...),
		httpClient:     nil, // built on demand, so a client never shares state with another
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		methods:        append([]Method(nil), defaultMethods...),
		attemptTimeout: defaultAttemptTimeout,
		lookup:         systemLookup,
		dial:           systemDial,
		rand:           defaultEntropy,
	}
}

// Option configures a Client. Options are applied in order, so a later one wins.
type Option func(*config)

// WithTimeout caps the total time a single discovery call may spend, regardless of the
// context it is given. The effective budget is the smaller of this and the context
// deadline. Zero, the default, means the context alone decides.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithAttemptTimeout sets the ceiling for one network attempt, defaulting to five
// seconds. An attempt also never exceeds a fair share of what the call has left, which
// is what keeps a stalled server from starving the rest of the list.
func WithAttemptTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.attemptTimeout = d
		}
	}
}

// WithMethods chooses which discovery methods to use, and the order they are tried in,
// for calls that do not name a method. An empty list keeps the default order.
func WithMethods(methods ...Method) Option {
	return func(c *config) {
		if len(methods) > 0 {
			c.methods = append([]Method(nil), methods...)
		}
	}
}

// WithSTUNServers replaces the STUN server list. Entries are "host:port".
func WithSTUNServers(servers ...string) Option {
	return func(c *config) { c.stunServers = append([]string(nil), servers...) }
}

// WithDNSServers replaces the DNS list. Each entry names a resolver and the query whose
// answer is the caller's address; the resolver may carry a port.
func WithDNSServers(servers ...DNSServer) Option {
	return func(c *config) { c.dnsServers = append([]DNSServer(nil), servers...) }
}

// WithHTTPEndpoints replaces the HTTP endpoints. Each must answer with a bare address.
func WithHTTPEndpoints(endpoints ...string) Option {
	return func(c *config) { c.httpEndpoints = append([]string(nil), endpoints...) }
}

// WithHTTPClient supplies the client used for HTTP discovery, for callers behind a proxy
// or with custom TLS. The address family is still forced per attempt.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// WithLogger sends debug output to l. Without it, discovery is silent. This replaces the
// v1 package-level flag and PUBLIC_IP_AUTODISCOVERY_DEBUG environment variable.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithMethod registers a Discoverer under name, replacing the built-in one when name is
// STUN, DNS or HTTP. Combine it with WithMethods to control the order, or to use only
// your own sources.
//
// An empty name or a nil Discoverer is ignored, so a conditional registration cannot
// silently disable a method.
func WithMethod(name Method, d Discoverer) Option {
	return func(c *config) {
		if name == "" || d == nil {
			return
		}
		if c.custom == nil {
			c.custom = make(map[Method]Discoverer)
		}
		c.custom[name] = d
	}
}
