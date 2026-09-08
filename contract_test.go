package publicip

import (
	"context"
	"errors"
	"testing"
)

// The frozen v1 error contract. v1 is a maintenance line: these assertions must keep
// passing unchanged. Callers are allowed to compare the sentinels with == and to
// match their text, so they must not be wrapped, renamed or enriched with causes -
// that redesign belongs to v2.

// TestV1ErrorContractFreeze pins the exact error values and messages v1 has always
// returned. v1 is a frozen maintenance line: any change here is a breaking change
// and belongs to v2, not to a patch release. In particular callers are allowed to
// compare these with == and to match the message text, so they must not be wrapped
// or enriched.
func TestV1ErrorContractFreeze(t *testing.T) {
	tests := []struct {
		err  error
		text string
	}{
		{ErrNoIPDiscovered, "no public IP could be discovered"},
		{ErrUnsupportedMethod, "unsupported discovery method"},
		{ErrUnsupportedIPVersion, "unsupported IP version"},
		{ErrTimeout, "discovery timed out"},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("sentinel disappeared")
			}
			if got := tt.err.Error(); got != tt.text {
				t.Errorf("error text = %q, want %q", got, tt.text)
			}
		})
	}

	// Distinctness: wrapping or aliasing sentinels would break callers that switch
	// on identity.
	sentinels := []error{ErrNoIPDiscovered, ErrUnsupportedMethod, ErrUnsupportedIPVersion, ErrTimeout}
	for i := range sentinels {
		for j := range sentinels {
			if i != j && sentinels[i] == sentinels[j] {
				t.Errorf("sentinels %q and %q are the same error", sentinels[i], sentinels[j])
			}
		}
	}
}

// TestV1AllMethodsFailReturnsBareSentinel asserts that a total failure returns
// ErrNoIPDiscovered by identity, not a wrapped variant of it.

func TestV1AllMethodsFailReturnsBareSentinel(t *testing.T) {
	failure := errors.New("network is unreachable")
	c := clientWith(map[Method]discoverer{
		STUN: fakeDiscoverer{name: STUN, err: failure},
		DNS:  fakeDiscoverer{name: DNS, err: failure},
		HTTP: fakeDiscoverer{name: HTTP, err: failure},
	})

	_, err := c.Discover(context.Background())
	if err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %#v, want exactly ErrNoIPDiscovered (==)", err)
	}
	if err.Error() != "no public IP could be discovered" {
		t.Fatalf("Discover() error text = %q, want the frozen v1 message", err.Error())
	}
	// The underlying causes must NOT leak into the returned error in v1.
	if errors.Is(err, failure) {
		t.Error("v1 must not expose the per-method causes; that redesign belongs to v2")
	}
}

// TestV1DiscovererFailureIsNotWrapped pins the per-method path as well.
func TestV1DiscovererFailureIsNotWrapped(t *testing.T) {
	c := clientWith(map[Method]discoverer{
		STUN: fakeDiscoverer{name: STUN, err: ErrNoIPDiscovered},
	})

	_, err := c.DiscoverWithMethod(context.Background(), STUN, Any)
	if err != ErrNoIPDiscovered {
		t.Fatalf("DiscoverWithMethod() error = %#v, want exactly ErrNoIPDiscovered", err)
	}
}

// --- IPVersion / Method values are part of the frozen surface --------------

func TestEnumValuesAreStable(t *testing.T) {
	// Any is the zero value, so `var v IPVersion` keeps working for callers.
	if Any != 0 {
		t.Errorf("Any = %d, want 0 (it is the zero value callers rely on)", Any)
	}
	if IPv4Only != 1 || IPv6Only != 2 {
		t.Errorf("IPVersion constants changed: IPv4Only=%d IPv6Only=%d", IPv4Only, IPv6Only)
	}
	if STUN != "stun" || DNS != "dns" || HTTP != "http" {
		t.Errorf("Method strings changed: %q %q %q", STUN, DNS, HTTP)
	}
}
