package publicip

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestLogDebugWritesWhenEnabled(t *testing.T) {
	var buf bytes.Buffer

	origDebug, origLogger := debug, debugLogger
	t.Cleanup(func() { debug, debugLogger = origDebug, origLogger })

	debug, debugLogger = true, log.New(&buf, "[PublicIP Debug] ", 0)

	logDebug("hello %s %d", "world", 7)

	got := buf.String()
	if !strings.HasPrefix(got, "[PublicIP Debug] hello world 7") {
		t.Errorf("log output = %q, want the formatted message with the debug prefix", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("log output = %q, want a trailing newline", got)
	}
}

func TestLogDebugSilentWhenDisabled(t *testing.T) {
	var buf bytes.Buffer

	origDebug, origLogger := debug, debugLogger
	t.Cleanup(func() { debug, debugLogger = origDebug, origLogger })

	debug, debugLogger = false, log.New(&buf, "", 0)
	logDebug("this must not appear")
	if buf.Len() != 0 {
		t.Errorf("logDebug wrote %q while disabled", buf.String())
	}

	// Enabled but with a nil logger must not panic: init() only allocates the
	// logger when the environment variable is set.
	debug, debugLogger = true, nil
	logDebug("still safe")
}

func TestDebugFlagDefaultsToOff(t *testing.T) {
	// The package is imported by the test binary before the test runs, so init()
	// has already read the environment. Tests in this package never set the
	// variable, which means the flag must be off; a leak here would silently
	// change behaviour for every other test.
	if debug {
		t.Error("debug logging is on by default; it must require PUBLIC_IP_AUTODISCOVERY_DEBUG")
	}
}
