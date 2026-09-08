package publicip

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// v2 replaced v1's bare sentinels with a DiscoveryError that wraps them together with
// the cause of every attempt. These tests define that contract: matching is done with
// errors.Is, and the detail of what failed is reachable rather than lost.

func TestDiscoveryErrorMatching(t *testing.T) {
	cause := errors.New("connect: network is unreachable")
	err := discoveryError(context.Background(), []Failure{
		{Method: STUN, Target: "192.0.2.1:3478", Family: "6", Err: cause},
	})

	if !errors.Is(err, ErrNotFound) {
		t.Error("errors.Is(err, ErrNotFound) = false, want true")
	}
	if errors.Is(err, ErrTimeout) {
		t.Error("errors.Is(err, ErrTimeout) = true on a run that was not cut short")
	}
	if !errors.Is(err, cause) {
		t.Error("the underlying cause is not reachable with errors.Is")
	}

	var de *DiscoveryError
	if !errors.As(err, &de) {
		t.Fatal("errors.As did not find the *DiscoveryError")
	}
	failures := de.Failures()
	if len(failures) != 1 {
		t.Fatalf("Failures() has %d entries, want 1", len(failures))
	}
	f := failures[0]
	if f.Method != STUN || f.Target != "192.0.2.1:3478" || f.Family != "6" {
		t.Errorf("failure = %+v, want the STUN IPv6 attempt that was recorded", f)
	}
	if de.TimedOut() {
		t.Error("TimedOut() = true, want false")
	}
}

func TestDiscoveryErrorTimeoutVersusCancellation(t *testing.T) {
	// A deadline and a cancellation are different diagnoses, and callers need to tell
	// them apart: one means the servers were too slow, the other means the caller quit.
	t.Run("deadline reached", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		time.Sleep(10 * time.Millisecond)

		err := discoveryError(ctx, []Failure{{
			Method: DNS, Target: "127.0.0.1:query", Family: "4", Err: ctx.Err(),
		}})

		if !errors.Is(err, ErrTimeout) {
			t.Errorf("errors.Is(err, ErrTimeout) = false, want true; error = %v", err)
		}
		if !errors.Is(err, ErrNotFound) {
			t.Error("a timed-out run must still satisfy errors.Is(err, ErrNotFound)")
		}
		if !strings.Contains(err.Error(), "deadline") {
			t.Errorf("Error() = %q, want it to say the budget ran out", err)
		}
		var de *DiscoveryError
		if errors.As(err, &de) && !de.TimedOut() {
			t.Error("TimedOut() = false, want true")
		}
	})

	t.Run("caller cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := discoveryError(ctx, []Failure{{
			Method: DNS, Target: "127.0.0.1:query", Family: "4", Err: ctx.Err(),
		}})

		if errors.Is(err, ErrTimeout) {
			t.Errorf("errors.Is(err, ErrTimeout) = true for a cancellation; error = %v", err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Error("the cancellation itself should stay reachable")
		}
		if !errors.Is(err, ErrNotFound) {
			t.Error("errors.Is(err, ErrNotFound) = false, want true")
		}
	})
}

// TestNoBudgetErrorReportsTheRealReason covers what the discoverers record when
// attemptBudget refuses an attempt.
func TestNoBudgetErrorReportsTheRealReason(t *testing.T) {
	if got := noBudgetError(context.Background()); got != context.DeadlineExceeded {
		t.Errorf("noBudgetError(background) = %v, want DeadlineExceeded", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := noBudgetError(ctx); got != context.Canceled {
		t.Errorf("noBudgetError(cancelled) = %v, want Canceled", got)
	}
}

func TestDiscoveryErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains []string
		absent   []string
	}{
		{
			name:     "no attempts recorded",
			err:      discoveryError(context.Background(), nil),
			contains: []string{"no public IP could be discovered"},
			absent:   []string{"more attempts"},
		},
		{
			name: "one failure names it",
			err: discoveryError(context.Background(), []Failure{
				{Method: HTTP, Target: "http://127.0.0.1:1", Family: "4", Err: errors.New("connection refused")},
			}),
			contains: []string{"http http://127.0.0.1:1 (ipv4): connection refused"},
			absent:   []string{"more attempts"},
		},
		{
			name: "many failures are summarised, not dumped",
			err: discoveryError(context.Background(), []Failure{
				{Method: STUN, Target: "192.0.2.1:3478", Family: "6", Err: errors.New("unreachable")},
				{Method: DNS, Target: "127.0.0.1:query", Family: "6", Err: errors.New("refused")},
				{Method: HTTP, Target: "http://127.0.0.1:1", Family: "6", Err: errors.New("refused")},
			}),
			contains: []string{"+2 more attempts"},
		},
		{
			name:     "a failure with no target still renders",
			err:      discoveryError(context.Background(), []Failure{{Method: STUN, Family: "4", Err: errors.New("boom")}}),
			contains: []string{"<no target>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Errorf("Error() = %q, want it to contain %q", got, want)
				}
			}
			for _, notWant := range tt.absent {
				if strings.Contains(got, notWant) {
					t.Errorf("Error() = %q, want it not to contain %q", got, notWant)
				}
			}
		})
	}
}

func TestFailuresOfForeignErrorIsStillAnError(t *testing.T) {
	// A caller-supplied discoverer may return anything; it must not vanish from the
	// aggregated report.
	boom := errors.New("custom discoverer exploded")
	err := discoveryError(context.Background(), failuresOf(boom))
	if !errors.Is(err, boom) {
		t.Error("a foreign error was dropped from the aggregated failure list")
	}
}

func TestSentinelsAreDistinct(t *testing.T) {
	sentinels := []error{ErrNotFound, ErrTimeout, ErrUnsupportedMethod}
	for i := range sentinels {
		for j := range sentinels {
			if i != j && sentinels[i] == sentinels[j] {
				t.Errorf("%q and %q are the same error", sentinels[i], sentinels[j])
			}
		}
	}
}

func TestResultRendering(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   string
	}{
		{
			name:   "ipv4 from STUN",
			result: Result{IP: net.IPv4(203, 0, 113, 9), Method: STUN, Version: IPv4Only},
			want:   "203.0.113.9 (stun/ipv4)",
		},
		{
			name:   "ipv6 from DNS",
			result: Result{IP: net.ParseIP("2001:db8::42"), Method: DNS, Version: IPv6Only},
			want:   "2001:db8::42 (dns/ipv6)",
		},
		{
			name:   "unknown method is labelled",
			result: Result{IP: net.IPv4(198, 51, 100, 1), Version: IPv4Only},
			want:   "198.51.100.1 (unknown/ipv4)",
		},
		{
			name:   "empty result does not panic",
			result: Result{},
			want:   "<empty result>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionOfReflectsTheAddressNotTheRequest(t *testing.T) {
	if got := versionOf(net.IPv4(127, 0, 0, 1)); got != IPv4Only {
		t.Errorf("versionOf(127.0.0.1) = %v, want IPv4Only", got)
	}
	if got := versionOf(net.ParseIP("2001:db8::1")); got != IPv6Only {
		t.Errorf("versionOf(2001:db8::1) = %v, want IPv6Only", got)
	}
	// The IPv4-in-IPv6 form reports as IPv4, which is what callers compare against.
	if got := versionOf(net.ParseIP("::ffff:198.51.100.7")); got != IPv4Only {
		t.Errorf("versionOf(::ffff:198.51.100.7) = %v, want IPv4Only", got)
	}
}

func TestEnumValuesAreStable(t *testing.T) {
	if Any != 0 {
		t.Errorf("Any = %d, want 0 (callers rely on the zero value)", Any)
	}
	if IPv4Only != 1 || IPv6Only != 2 {
		t.Errorf("IPVersion constants changed: IPv4Only=%d IPv6Only=%d", IPv4Only, IPv6Only)
	}
	if STUN != "stun" || DNS != "dns" || HTTP != "http" {
		t.Errorf("Method strings changed: %q %q %q", STUN, DNS, HTTP)
	}
}

func TestDiscoveryErrorDetailListsEveryFailure(t *testing.T) {
	err := discoveryError(context.Background(), []Failure{
		{Method: STUN, Target: "192.0.2.1:3478", Family: "6", Err: errors.New("network unreachable")},
		{Method: DNS, Target: "198.51.100.1:53", Family: "4", Err: errors.New("read: connection refused")},
	})

	var de *DiscoveryError
	if !errors.As(err, &de) {
		t.Fatal("want a *DiscoveryError")
	}

	got := de.Detail()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 2 {
		t.Fatalf("Detail() has %d lines, want 2:\n%s", len(lines), got)
	}
	if !strings.Contains(lines[0], "stun 192.0.2.1:3478 (ipv6): network unreachable") {
		t.Errorf("line 1 = %q, want the STUN attempt", lines[0])
	}
	if !strings.Contains(lines[1], "dns 198.51.100.1:53 (ipv4): read: connection refused") {
		t.Errorf("line 2 = %q, want the DNS attempt", lines[1])
	}

	// Error() stays a single line; Detail() is where the rest lives.
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("Error() = %q, want a one-line summary", err.Error())
	}
	if !strings.Contains(err.Error(), "+1 more attempts") {
		t.Errorf("Error() = %q, want it to mention the suppressed failure", err.Error())
	}
}
