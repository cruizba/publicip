package publicip

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// logSink records every slog record as a single line, message and attributes
// interleaved. Asserting on it is the only way to know WithLogger does something:
// a debug call nobody checks is a debug call that can be deleted silently, and
// mutation testing found exactly that set of survivors.
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *logSink) Enabled(context.Context, slog.Level) bool { return true }

func (s *logSink) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Level.String())
	b.WriteString(" ")
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" ")
		b.WriteString(a.Key)
		b.WriteString("=")
		b.WriteString(a.Value.String())
		return true
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, b.String())
	return nil
}

func (s *logSink) WithAttrs([]slog.Attr) slog.Handler { return s }
func (s *logSink) WithGroup(string) slog.Handler      { return s }

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

func (s *logSink) has(want string) bool { return strings.Contains(s.String(), want) }

func TestClientLoggingCoversTheWholeLifecycle(t *testing.T) {
	sink := &logSink{}
	logger := slog.New(sink)

	var calls []string
	c := clientWith(map[Method]discoverer{
		STUN: fakeDiscoverer{name: STUN, err: errors.New("no route to host"), calls: &calls},
		DNS:  fakeDiscoverer{name: DNS, ip: "203.0.113.31", calls: &calls},
	})
	c.config.logger = logger

	// One success: the failing method, the winning method, and the outcome are logged.
	if _, err := c.Discover(context.Background()); err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	for _, want := range []string{
		`DEBUG method failed method=stun error=no route to host`,
		`DEBUG address discovered method=dns ip=203.0.113.31`,
	} {
		if !sink.has(want) {
			t.Errorf("log is missing %q, got:\n[%s]", want, sink.String())
		}
	}

	// An unsupported method and an unconfigured one are both reported, not swallowed.
	if _, err := c.DiscoverWithMethod(context.Background(), Method("carrier-pigeon"), Any); !errors.Is(err, ErrUnsupportedMethod) {
		t.Fatalf("DiscoverWithMethod() error = %v", err)
	}
	if !sink.has(`DEBUG unsupported method method=carrier-pigeon`) {
		t.Errorf("unsupported method was not logged, got:\n%s", sink.String())
	}

	only := newTestClient(t, WithLogger(logger), WithMethods(Method("gps"), HTTP))
	if _, err := only.Discover(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound from sandboxed endpoints", err)
	}
	for _, want := range []string{
		`DEBUG skipping unconfigured method method=gps`,
		"DEBUG all discovery methods failed",
	} {
		if !sink.has(want) {
			t.Errorf("log is missing %q, got:\n%s", want, sink.String())
		}
	}
}

func TestDiscovererLoggingNamesEveryFailedTarget(t *testing.T) {
	sink := &logSink{}
	addr := startStunServer(t, "udp4", silentServer)

	d := newSTUNDiscoverer(testConfig(
		WithSTUNServers(addr, "127.0.0.1:1"),
		attemptTimeout(120*time.Millisecond),
		WithLogger(slog.New(sink)),
	))

	if _, err := d.Discover(context.Background(), IPv4Only); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v", err)
	}
	for _, want := range []string{
		"DEBUG attempt failed method=stun family=4",
		"DEBUG method exhausted method=stun attempts=2",
	} {
		if !sink.has(want) {
			t.Errorf("log is missing %q, got:\n%s", want, sink.String())
		}
	}
}

func TestLoggerIgnoresNilAndDiscardsByDefault(t *testing.T) {
	// WithLogger(nil) must not install a nil logger, and the default must swallow
	// everything rather than writing to stderr the way v1's environment variable did.
	silent := newTestClient(t, WithLogger(nil))
	if silent.config.logger == nil {
		t.Fatal("WithLogger(nil) cleared the logger")
	}

	sink := &logSink{}
	loud := newTestClient(t, WithLogger(slog.New(sink)))
	if loud.config.logger == silent.config.logger {
		t.Error("WithLogger did not replace the default logger")
	}

	// The injected logger must actually receive the lifecycle of its own client.
	if _, err := loud.Discover(context.Background()); err == nil {
		t.Fatal("want a failure against a closed port")
	}
	if len(sink.lines) == 0 {
		t.Error("WithLogger installed a logger that is never used")
	}
	if !sink.has("attempt failed") {
		t.Errorf("sink got %q, want the failed attempt reported", sink.String())
	}

	// The default client writes nowhere: no stderr, no panic, no global state.
	if _, err := silent.Discover(context.Background()); err == nil {
		t.Fatal("want a failure against a closed port")
	}
}

func TestFamilyGuardLogsTheMismatch(t *testing.T) {
	sink := &logSink{}
	c := newTestClient(t,
		WithLogger(slog.New(sink)),
		WithMethod("custom", wrongFamily{ip: "203.0.113.44"}),
		WithMethods("custom"),
	)

	if _, err := c.DiscoverWithIPVersion(context.Background(), IPv6Only); err == nil {
		t.Fatal("want the family mismatch rejected")
	}
	if !sink.has("method returned the wrong family") {
		t.Errorf("the mismatch was not logged, got:\n%s", sink.String())
	}
}
