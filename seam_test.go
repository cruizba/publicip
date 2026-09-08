package publicip

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// These tests exist because the seams make failure branches reachable. Everything here
// would otherwise need a real network fault: a server that dies mid-write, a TLS peer
// that is not speaking TLS, a read that never returns.

type fakeConn struct {
	net.Conn
	readErr  error
	writeErr error
	deadline error
	read     func([]byte) (int, error)
}

func (c fakeConn) Read(b []byte) (int, error) {
	if c.read != nil {
		return c.read(b)
	}
	return 0, c.readErr
}

func (c fakeConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(b), nil
}

func (c fakeConn) Close() error { return nil }

func (c fakeConn) SetDeadline(time.Time) error { return c.deadline }

// --- STUN -----------------------------------------------------------------

func TestSTUNDialErrorIsRecorded(t *testing.T) {
	boom := errors.New("network is unreachable")
	d := newSTUNDiscoverer(testConfig(
		WithSTUNServers("192.0.2.1:3478"),
		attemptTimeout(time.Second),
		withDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "udp4" {
				t.Errorf("dialed %s, want the forced udp4", network)
			}
			return nil, boom
		}),
	))

	_, err := d.Discover(context.Background(), IPv4Only)
	if !errors.Is(err, boom) {
		t.Errorf("Discover() error = %v, want the dial failure to be reachable", err)
	}
}

func TestSTUNWriteErrorIsRecorded(t *testing.T) {
	boom := errors.New("sendto: operation not permitted")
	d := newSTUNDiscoverer(testConfig(
		WithSTUNServers("192.0.2.1:3478"),
		attemptTimeout(time.Second),
		withDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return fakeConn{writeErr: boom}, nil
		}),
	))

	_, err := d.Discover(context.Background(), IPv4Only)
	if !errors.Is(err, boom) {
		t.Errorf("Discover() error = %v, want the write failure", err)
	}
}

func TestSTUNShortReadIsHandled(t *testing.T) {
	// A server that answers with fewer bytes than a header needs.
	d := newSTUNDiscoverer(testConfig(
		WithSTUNServers("192.0.2.1:3478"),
		attemptTimeout(time.Second),
		withDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return fakeConn{read: func(b []byte) (int, error) {
				copy(b, []byte{0x01, 0x01})
				return 2, nil
			}}, nil
		}),
	))

	if _, err := d.Discover(context.Background(), IPv4Only); err == nil ||
		!strings.Contains(err.Error(), "response too short") {
		t.Errorf("Discover() error = %v, want the truncated-response report", err)
	}
}

// --- HTTP -----------------------------------------------------------------

func TestHTTPResponseSizeIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("f", 4096))
	}))
	defer srv.Close()

	d := httpClient([]string{srv.URL}, 2*time.Second)
	_, err := d.Discover(context.Background(), IPv4Only)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("Discover() error = %v, want the size limit to fire", err)
	}
}

func TestHTTPMalformedEndpointFailsBeforeDialing(t *testing.T) {
	d := httpClient([]string{"http://%zz"}, time.Second)
	if _, err := d.Discover(context.Background(), IPv4Only); err == nil {
		t.Fatal("Discover() = nil, want a request-construction error")
	} else if !strings.Contains(err.Error(), "failed to create request") {
		t.Errorf("error = %v, want the request-construction stage named", err)
	}
}

func TestHTTPSToAPlainListenerIsReported(t *testing.T) {
	// A plain HTTP endpoint advertised as https: the TLS handshake fails. With the
	// handshake now performed by net/http on our dialed connection, the caller's context
	// bounds it, which is what the v1 tls.DialWithDialer call could not do.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "192.0.2.5\n")
	}))
	defer plain.Close()

	host, port, err := net.SplitHostPort(strings.TrimPrefix(plain.URL, "http://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	d := httpClient([]string{"https://" + net.JoinHostPort(host, port)}, 2*time.Second)
	if _, err := d.Discover(context.Background(), IPv4Only); err == nil {
		t.Fatal("Discover() = nil, want a TLS failure against a plain listener")
	}
}

func TestHTTPHonoursServerCertificate(t *testing.T) {
	// The transport is cloned from the base, so a caller who supplies a client trusting a
	// test CA still gets TLS verification through it.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "198.51.100.9\n")
	}))
	defer srv.Close()

	d := newHTTPDiscoverer(testConfig(
		WithHTTPEndpoints(srv.URL),
		attemptTimeout(2*time.Second),
		WithHTTPClient(srv.Client()),
	))
	res, err := d.Discover(context.Background(), IPv4Only)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := res.IP.String(); got != "198.51.100.9" {
		t.Errorf("Discover() = %v, want 198.51.100.9", got)
	}
}

func TestHTTPClientWithCustomRoundTripperIsLeftAlone(t *testing.T) {
	// A RoundTripper that is not an *http.Transport decides its own addressing; the
	// discoverer must not fail just because it cannot force a family onto it.
	called := 0
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		called++
		return httptest.NewRecorder().Result(), nil
	})
	d := newHTTPDiscoverer(testConfig(
		WithHTTPEndpoints("http://127.0.0.1:1"),
		attemptTimeout(time.Second),
		WithHTTPClient(&http.Client{Transport: rt}),
	))

	if _, err := d.Discover(context.Background(), IPv4Only); err == nil {
		t.Fatal("want the empty response to be rejected as an invalid address")
	}
	if called == 0 {
		t.Error("the caller's RoundTripper was never used")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestHTTPSharesOneConnectionPoolPerFamily(t *testing.T) {
	d := httpClient([]string{"http://127.0.0.1:1"}, time.Second)
	if d.clients["4"] == d.clients["6"] {
		t.Fatal("the two families share one client, so the family is not forced")
	}
	t4, ok4 := d.clients["4"].Transport.(*http.Transport)
	t6, ok6 := d.clients["6"].Transport.(*http.Transport)
	if !ok4 || !ok6 {
		t.Fatal("expected per-family transports")
	}
	if t4.DialContext == nil || t6.DialContext == nil {
		t.Error("a family transport without a dialer cannot force the family")
	}
}

// --- TLS sanity -----------------------------------------------------------

func TestSystemDialRefusesWhenNothingListens(t *testing.T) {
	// Closes the loop on why the handshake moved: a dial of a closed loopback port fails
	// immediately rather than waiting for a timeout nobody can cancel.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	_, err := systemDial(ctx, "tcp4", "127.0.0.1:1")
	if err == nil {
		t.Fatal("systemDial() = nil error, want a refusal")
	}
	if time.Since(start) > time.Second {
		t.Errorf("systemDial() took %v, want an immediate refusal", time.Since(start))
	}
}

func TestTLSHandshakeIsNotPinnedToBackground(t *testing.T) {
	// Regression guard for v1's tls.DialWithDialer, which uses context.Background()
	// internally: cancelling the caller's context has to interrupt the attempt.
	block := make(chan struct{})
	defer close(block)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block // never answers
	}))
	srv.Config.ErrorLog = nil
	srv.Start()
	defer srv.Close()

	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	d := newHTTPDiscoverer(testConfig(
		WithHTTPEndpoints("https://127.0.0.1:"+port),
		attemptTimeout(30*time.Second),
	))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if _, err := d.Discover(ctx, IPv4Only); err == nil {
		t.Fatal("Discover() = nil, want the cancellation to end the attempt")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Discover() took %v after cancellation; the request must not outlive the context", elapsed)
	}
}

func TestSTUNDeadlineFailureIsReported(t *testing.T) {
	boom := errors.New("setdeadline: invalid argument")
	d := newSTUNDiscoverer(testConfig(
		WithSTUNServers("192.0.2.1:3478"),
		attemptTimeout(time.Second),
		withDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return fakeConn{deadline: boom}, nil
		}),
	))

	_, err := d.Discover(context.Background(), IPv4Only)
	if !errors.Is(err, boom) {
		t.Errorf("Discover() error = %v, want the deadline-setup failure", err)
	}
}

// bodyErrReader fails partway through the body, which only a transport can produce: a
// truncated chunked response or a connection dropped mid-transfer.
type bodyErrReader struct{}

func (bodyErrReader) Read([]byte) (int, error) { return 0, errors.New("unexpected EOF") }

func TestHTTPBodyReadErrorIsReported(t *testing.T) {
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bodyErrReader{}),
			Header:     make(http.Header),
		}, nil
	})
	d := newHTTPDiscoverer(testConfig(
		WithHTTPEndpoints("http://127.0.0.1:1"),
		attemptTimeout(time.Second),
		WithHTTPClient(&http.Client{Transport: rt}),
	))

	_, err := d.Discover(context.Background(), IPv4Only)
	if err == nil || !strings.Contains(err.Error(), "failed to read response") {
		t.Errorf("Discover() error = %v, want the body-read stage named", err)
	}
}

func TestRunTreatsNilIPWithNilErrorAsNoAnswer(t *testing.T) {
	// An implementation that returns (nil, nil) is broken, not successful. The round
	// runner must report it rather than handing the caller a zero Result.
	cfg := cfgFor(attemptTimeout(time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, failures := runRound(cfg, ctx, STUN, []round[string]{{"192.0.2.1:3478", "4"}},
		time.Second,
		func(ctx context.Context, target, family string, timeout time.Duration) (net.IP, error) {
			return nil, nil
		}, identity)

	if len(failures) != 1 {
		t.Fatalf("failures = %d, want 1", len(failures))
	}
	if !errors.Is(failures[0].Err, ErrNotFound) {
		t.Errorf("failure error = %v, want ErrNotFound for a result-less success", failures[0].Err)
	}
}

func TestHTTPForcesTheAddressFamilyInTheDial(t *testing.T) {
	// Removing the DialContext assignment survives a behavioural test, because the
	// family check after parsing rejects the same answer either way. What has to be
	// asserted is the dial itself: an IPv6 request must go out as tcp6.
	var seen []string
	d := newHTTPDiscoverer(testConfig(
		WithHTTPEndpoints("http://127.0.0.1:1"),
		attemptTimeout(200*time.Millisecond),
		withDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			seen = append(seen, network)
			return nil, errors.New("no route")
		}),
	))

	//nolint:errcheck // the outcome is asserted through the recorded networks
	d.Discover(context.Background(), Any)

	if len(seen) != 2 || seen[0] != "tcp6" || seen[1] != "tcp4" {
		t.Errorf("dialed %v, want [tcp6 tcp4] in that order", seen)
	}
}

func TestHTTPAcceptsABodyOfExactlyTheLimit(t *testing.T) {
	// The bound is "larger than", so a body of exactly maxAddressBodyBytes must still
	// be accepted. An off-by-one mutant would reject it and only this edge catches it.
	ip := "203.0.113.200"
	prefix := strings.Repeat(" ", maxAddressBodyBytes-len(ip))
	srv := httptest.NewServer(stubIP(prefix + ip))
	defer srv.Close()

	d := httpClient([]string{srv.URL}, 2*time.Second)
	res, err := d.Discover(context.Background(), IPv4Only)
	if err != nil {
		t.Fatalf("Discover() error = %v, want a body of exactly %d bytes accepted", err, maxAddressBodyBytes)
	}
	if got := res.IP.String(); got != ip {
		t.Errorf("Discover() = %v, want %s after trimming the padding", got, ip)
	}

	// One byte more is refused.
	over := httptest.NewServer(stubIP(" " + prefix + ip))
	defer over.Close()

	d2 := httpClient([]string{over.URL}, 2*time.Second)
	if _, err := d2.Discover(context.Background(), IPv4Only); err == nil ||
		!strings.Contains(err.Error(), "larger than") {
		t.Errorf("Discover() error = %v, want the size limit to fire one byte past it", err)
	}
}
