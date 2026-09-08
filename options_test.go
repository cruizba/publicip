package publicip

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestWithHTTPClientIsUsed(t *testing.T) {
	provided := &http.Client{}
	c := New(WithHTTPClient(provided))
	if c.config.httpClient != provided {
		t.Error("WithHTTPClient did not reach the config")
	}

	// The zero-value client option must be a no-op rather than a nil client, which
	// would panic on first use.
	if New().config.httpClient != nil {
		t.Error("default config should not carry an http.Client")
	}
}

// captureHandler is a minimal slog.Handler that records one record.
type captureHandler struct {
	buf   *bytes.Buffer
	attrs []slog.Attr
}

func (h *captureHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelDebug
}

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.buf.WriteString(r.Level.String())
	h.buf.WriteString(" ")
	h.buf.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		h.attrs = append(h.attrs, a)
		return true
	})
	return nil
}

func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

func TestWithLoggerReceivesDebugOutput(t *testing.T) {
	var buf bytes.Buffer
	handler := &captureHandler{buf: &buf}
	c := newTestClient(t, WithLogger(slog.New(handler)), WithSTUNServers("127.0.0.1:1"))

	if _, err := c.DiscoverWithMethod(context.Background(), STUN, IPv4Only); err == nil {
		t.Fatal("DiscoverWithMethod() = nil, want a failure against a closed port")
	}
	if buf.Len() == 0 {
		t.Fatal("the configured logger received nothing")
	}
	if !strings.Contains(buf.String(), "attempt failed") {
		t.Errorf("log output = %q, want it to mention the failed attempt", buf.String())
	}

	// Attributes, not fmt.Sprintf: the point of taking a *slog.Logger.
	var target string
	for _, a := range handler.attrs {
		if a.Key == "target" {
			target = a.Value.String()
		}
	}
	if target != "127.0.0.1:1" {
		t.Errorf("target attribute = %q, want 127.0.0.1:1", target)
	}
}

func TestWithoutLoggerNothingIsWritten(t *testing.T) {
	// The discard handler must swallow everything rather than panic.
	c := newTestClient(t)
	if _, err := c.Discover(context.Background()); err == nil {
		t.Fatal("want a failure against closed loopback ports")
	}
}

func TestCallContextAppliesClientTimeout(t *testing.T) {
	c := New(WithTimeout(150 * time.Millisecond))

	ctx, cancel := c.callContext(context.Background())
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("callContext() returned a context with no deadline")
	}
	if remaining := time.Until(deadline); remaining > 150*time.Millisecond || remaining <= 0 {
		t.Errorf("deadline in %v, want at most the configured 150ms", remaining)
	}
}

func TestCallContextDefersToCallerWhenUnset(t *testing.T) {
	c := New() // timeout 0

	ctx, cancel := c.callContext(context.Background())
	defer cancel()

	if _, ok := ctx.Deadline(); ok {
		t.Error("callContext() invented a deadline; the default is to leave the caller's context alone")
	}
	if ctx.Done() != nil {
		t.Error("the returned context should be the caller's own, with no extra cancel channel")
	}
}

func TestDefaultsAreIndependentCopies(t *testing.T) {
	// Two clients built from defaults must not share backing arrays, or mutating one
	// through an option would be visible in the other.
	a := New(WithSTUNServers("192.0.2.1:3478"))
	b := New()
	if len(a.config.stunServers) != 1 || len(b.config.stunServers) != 3 {
		t.Errorf("a=%v b=%v, want the second client untouched", a.config.stunServers, b.config.stunServers)
	}

	first := defaultConfig()
	first.stunServers[0] = "mutated"
	if defaultConfig().stunServers[0] == "mutated" {
		t.Error("defaultConfig() shares its slices between calls")
	}
}

func TestDefaultEndpointShapes(t *testing.T) {
	for _, server := range defaultSTUNServers {
		if host, port, err := net.SplitHostPort(server); err != nil || host == "" || port == "" {
			t.Errorf("STUN default %q is not host:port", server)
		}
	}
	for _, server := range defaultDNSServers {
		if parts := strings.Split(server, ":"); len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			t.Errorf("DNS default %q must be resolver:query-name", server)
		}
	}
	for _, endpoint := range defaultHTTPEndpoints {
		if !strings.HasPrefix(endpoint, "https://") {
			t.Errorf("HTTP default %q is not https", endpoint)
		}
	}
}
