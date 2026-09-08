package main

import (
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The CLI is tested through run(), which reads the process flags and writes to
// stdout/stderr. resetFlags restores the package-level flag variables between
// cases: flag.Parse only assigns the flags present in os.Args, so leftovers from a
// previous case would otherwise leak into the next one.
//
// Only the paths that do not need the network are exercised here: argument
// validation, -version, -help and the failure path (a zero timeout exhausts the
// context before any dial, which v1.2.2 guarantees returns immediately). The
// success path needs run() to accept the client as a dependency, which is a v2
// change; it is covered by the nightly integration suite instead.

var semverTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

func resetFlags() {
	ipVersion = ""
	method = ""
	timeout = 10
	showVersion = false
	showHelp = false
}

// runCLI invokes run() with the given arguments and returns its error together
// with whatever it wrote to stdout and stderr.
func runCLI(t *testing.T, args ...string) (runErr error, stdout, stderr string) {
	t.Helper()

	resetFlags()
	t.Cleanup(resetFlags)

	oldArgs := os.Args
	os.Args = append([]string{"publicip"}, args...)
	defer func() { os.Args = oldArgs }()

	outR, outW, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("pipe: %v", pipeErr)
	}
	errR, errW, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("pipe: %v", pipeErr)
	}

	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()

	runErr = run()

	outW.Close()
	errW.Close()
	b, _ := io.ReadAll(outR)
	e, _ := io.ReadAll(errR)

	return runErr, string(b), string(e)
}

func TestRunVersion(t *testing.T) {
	for _, flag := range []string{"-version", "-v"} {
		err, stdout, _ := runCLI(t, flag)
		if err != nil {
			t.Fatalf("%s: run() error = %v", flag, err)
		}
		got := strings.TrimSpace(stdout)
		if !semverTag.MatchString(got) {
			t.Errorf("%s printed %q, want a vMAJOR.MINOR.PATCH tag", flag, got)
		}
	}
}

func TestRunHelp(t *testing.T) {
	for _, flag := range []string{"-help", "-h"} {
		err, _, stderr := runCLI(t, flag)
		if err != nil {
			t.Fatalf("%s: run() error = %v", flag, err)
		}
		if !strings.Contains(stderr, "Usage:") {
			t.Errorf("%s did not print the usage text, stderr = %q", flag, stderr)
		}
	}
}

func TestRunRejectsInvalidArguments(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"ip version 5", []string{"-ip-version", "5"}, "invalid ip-version"},
		{"ip version short", []string{"-i", "banana"}, "invalid ip-version"},
		{"unknown method", []string{"-method", "carrier-pigeon"}, "invalid method"},
		{"unknown method short", []string{"-m", "udp"}, "invalid method"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err, _, _ := runCLI(t, tt.args...)
			if err == nil {
				t.Fatalf("run(%v) = nil, want an error containing %q", tt.args, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("run(%v) error = %q, want it to contain %q", tt.args, err, tt.wantErr)
			}
		})
	}
}

// TestRunEmptyTimeoutFailsFast pins the v1.2.2 behaviour: with no time budget the
// CLI must return an error promptly instead of dialing every configured server.
func TestRunEmptyTimeoutFailsFast(t *testing.T) {
	for _, args := range [][]string{
		{"-timeout", "0"},
		{"-t", "0", "-method", "stun"},
		{"-t", "0", "-method", "dns"},
		{"-t", "0", "-method", "http"},
		{"-t", "0", "-i", "4"},
		{"-t", "0", "-i", "6"},
	} {
		start := time.Now()
		err, stdout, _ := runCLI(t, args...)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatalf("run(%v) = nil error with %q on stdout, want a discovery failure", args, stdout)
		}
		if !strings.Contains(err.Error(), "no public IP") {
			t.Errorf("run(%v) error = %q, want the frozen v1 failure", args, err)
		}
		if elapsed > 5*time.Second {
			t.Errorf("run(%v) took %v with an empty budget; it must not dial the servers", args, elapsed)
		}
	}
}
