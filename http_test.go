package publicip

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func httpClient(endpoints []string, timeout time.Duration) *httpDiscoverer {
	return newHTTPDiscovererWithConfig(timeout, HTTPConfig{Endpoints: endpoints})
}

// stubIP returns an HTTP handler that answers with the given body.
func stubIP(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
}

func TestHTTPDiscoverIPv4(t *testing.T) {
	srv := httptest.NewServer(stubIP("203.0.113.9\n"))
	defer srv.Close()

	d := httpClient([]string{srv.URL}, 2*time.Second)
	ip, err := d.Discover(context.Background(), IPv4Only)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := ip.String(); got != "203.0.113.9" {
		t.Errorf("Discover() = %s, want 203.0.113.9", got)
	}
}

func TestHTTPDiscoverIPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	srv := httptest.NewUnstartedServer(stubIP("2001:db8::42\n"))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	d := httpClient([]string{srv.URL}, 2*time.Second)
	ip, err := d.Discover(context.Background(), IPv6Only)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := ip.String(); got != "2001:db8::42" {
		t.Errorf("Discover() = %s, want 2001:db8::42", got)
	}
}

func TestHTTPTrimsAndParsesBody(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"trailing newline", "198.51.100.1\n", "198.51.100.1"},
		{"surrounding whitespace", "  \r\n198.51.100.2 \t\n", "198.51.100.2"},
		{"no trailing newline", "198.51.100.3", "198.51.100.3"},
		{"IPv6 mapped form accepted", "::ffff:198.51.100.4", "198.51.100.4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(stubIP(tt.body))
			defer srv.Close()

			d := httpClient([]string{srv.URL}, 2*time.Second)
			ip, err := d.Discover(context.Background(), IPv4Only)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if got := ip.String(); got != tt.want {
				t.Errorf("Discover() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestHTTPRejectsUnparsableBodies(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"html page", "<!doctype html><html><body>404</body></html>"},
		{"json payload", `{"ip":"198.51.100.5"}`},
		{"two addresses", "198.51.100.6\n198.51.100.7\n"},
		{"not an address", "not-an-ip"},
		{"truncated octet", "198.51.100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(stubIP(tt.body))
			defer srv.Close()

			d := httpClient([]string{srv.URL}, 2*time.Second)
			if _, err := d.Discover(context.Background(), IPv4Only); err != ErrNoIPDiscovered {
				t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
			}
		})
	}
}

func TestHTTPStatusIsNotChecked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("192.0.2.77"))
	}))
	defer srv.Close()

	d := httpClient([]string{srv.URL}, 2*time.Second)
	ip, err := d.Discover(context.Background(), IPv4Only)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := ip.String(); got != "192.0.2.77" {
		t.Errorf("Discover() = %s, want 192.0.2.77", got)
	}
}

func TestHTTPFallsThroughEndpointList(t *testing.T) {
	good := httptest.NewServer(stubIP("192.0.2.10"))
	defer good.Close()

	dead := httptest.NewServer(stubIP("garbage"))
	defer dead.Close()

	d := httpClient([]string{dead.URL, "http://127.0.0.1:1", good.URL}, 2*time.Second)
	ip, err := d.Discover(context.Background(), IPv4Only)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := ip.String(); got != "192.0.2.10" {
		t.Errorf("Discover() = %s, want the third endpoint's answer 192.0.2.10", got)
	}
}

func TestHTTPAllEndpointsFail(t *testing.T) {
	d := httpClient([]string{"http://127.0.0.1:1", "http://[::1]:1"}, 500*time.Millisecond)
	if _, err := d.Discover(context.Background(), IPv4Only); err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
	}
}

func TestHTTPMalformedEndpoint(t *testing.T) {
	d := httpClient([]string{"http://%zz"}, time.Second)
	if _, err := d.Discover(context.Background(), IPv4Only); err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
	}
}

// TestHTTPResponseIsNotFollowedToGarbage pins that v1 follows redirects with the
// default http.Client and accepts whatever the final endpoint answers.
func TestHTTPResponseIsNotFollowedToGarbage(t *testing.T) {
	final := httptest.NewServer(stubIP("192.0.2.20"))
	defer final.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/redirect") {
			http.Redirect(w, r, final.URL, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusFound)
	}))
	defer redirect.Close()

	d := httpClient([]string{redirect.URL + "/redirect"}, 2*time.Second)
	ip, err := d.Discover(context.Background(), IPv4Only)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := ip.String(); got != "192.0.2.20" {
		t.Errorf("Discover() = %s, want 192.0.2.20", got)
	}
}
