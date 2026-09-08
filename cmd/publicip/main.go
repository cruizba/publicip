package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	publicip "github.com/cruizba/publicip/v2"
)

const usageText = `publicip - discover your public IP address over STUN, DNS and HTTP

Usage:
  publicip [flags]

Flags:
  -i, --ip-version string   IP version to discover: 4 or 6
  -m, --method string       discovery method to use: stun, dns or http
  -a, --all                 try every method and family, print each distinct address
  -j, --json                print a JSON document instead of a bare address
  -v, --verbose             report how the address was found, and what failed
  -t, --timeout int         overall budget in seconds (default 10)
      --version             print the version and exit
  -h, --help                show this help

Examples:
  publicip                     first address found, IPv6 preferred
  publicip -i 4 -m stun       IPv4 over STUN only
  publicip -a -j              every address the three methods can reach, as JSON
`

// cli holds the process boundaries. Everything is a field so run() can be driven from a
// test with buffers and a fake client factory; main() is the only thing that touches the
// real ones.
type cli struct {
	stdout    io.Writer
	stderr    io.Writer
	newClient func(opts ...publicip.Option) *publicip.Client
}

type jsonOutput struct {
	Addresses []jsonAddress `json:"addresses"`
	Errors    []string      `json:"errors,omitempty"`
}

type jsonAddress struct {
	IP      string `json:"ip"`
	Method  string `json:"method"`
	Family  string `json:"family"`
	Latency string `json:"latency,omitempty"`
}

func (c *cli) run(args []string) error {
	var (
		ipVersion   string
		method      string
		all         bool
		asJSON      bool
		verbose     bool
		timeout     int
		showVersion bool
	)

	fs := flag.NewFlagSet("publicip", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() { fmt.Fprint(c.stderr, usageText) }

	fs.StringVar(&ipVersion, "ip-version", "", "IP version to discover (4 or 6)")
	fs.StringVar(&ipVersion, "i", "", "IP version to discover (4 or 6)")
	fs.StringVar(&method, "method", "", "discovery method (stun, dns or http)")
	fs.StringVar(&method, "m", "", "discovery method (stun, dns or http)")
	fs.BoolVar(&all, "all", false, "try every method and family")
	fs.BoolVar(&all, "a", false, "try every method and family")
	fs.BoolVar(&asJSON, "json", false, "print JSON instead of a bare address")
	fs.BoolVar(&asJSON, "j", false, "print JSON instead of a bare address")
	fs.BoolVar(&verbose, "verbose", false, "report how the address was found")
	fs.BoolVar(&verbose, "v", false, "report how the address was found")
	fs.IntVar(&timeout, "timeout", 10, "overall budget in seconds")
	fs.IntVar(&timeout, "t", 10, "overall budget in seconds")
	fs.BoolVar(&showVersion, "version", false, "print the version and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // the usage text was already printed
		}
		return err
	}

	if showVersion {
		fmt.Fprintln(c.stdout, publicip.Version())
		return nil
	}

	version, err := parseVersion(ipVersion)
	if err != nil {
		return err
	}
	m, err := parseMethod(method)
	if err != nil {
		return err
	}
	if timeout <= 0 {
		return fmt.Errorf("invalid timeout: %d (must be a positive number of seconds)", timeout)
	}

	client := c.newClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	return c.report(ctx, client, m, version, all, asJSON, verbose, timeout)
}

// report performs the discovery the flags asked for and writes it out.
func (c *cli) report(ctx context.Context, client *publicip.Client, m publicip.Method, version publicip.IPVersion, all, asJSON, verbose bool, timeout int) error {
	if all {
		return c.reportAll(ctx, client, version, asJSON, verbose, timeout)
	}

	start := time.Now()
	result, err := discover(ctx, client, m, version)
	if err != nil {
		if verbose {
			c.describeFailure(err)
		}
		return err
	}

	elapsed := time.Since(start)
	if asJSON {
		return c.encodeJSON([]publicip.Result{result}, nil, elapsed)
	}
	fmt.Fprintln(c.stdout, result.IP.String())
	if verbose {
		fmt.Fprintf(c.stderr, "found %s in %s\n", result, elapsed.Round(time.Millisecond))
	}
	return nil
}

// discover routes to the method-specific call when one was named, so the reported
// Result.Method is only constrained by the caller when they asked for it.
func discover(ctx context.Context, client *publicip.Client, m publicip.Method, version publicip.IPVersion) (publicip.Result, error) {
	switch {
	case m != "":
		return client.DiscoverWithMethod(ctx, m, version)
	case version != publicip.Any:
		return client.DiscoverWithIPVersion(ctx, version)
	default:
		return client.Discover(ctx)
	}
}

// found is one address plus the probe that produced it, so --all --json can report a
// per-address latency instead of a made-up one.
type found struct {
	result  publicip.Result
	latency time.Duration
}

// reportAll walks every method, for the requested family or for both, and keeps the
// distinct addresses. This is the mode that answers "what does the world see me as",
// which is the question a single address cannot answer on a dual-stack host.
func (c *cli) reportAll(ctx context.Context, client *publicip.Client, version publicip.IPVersion, asJSON, verbose bool, timeout int) error {
	methods := []publicip.Method{publicip.STUN, publicip.DNS, publicip.HTTP}
	families := []publicip.IPVersion{publicip.IPv6Only, publicip.IPv4Only}
	if version != publicip.Any {
		families = []publicip.IPVersion{version}
	}

	var (
		findings []found
		seen     = map[string]bool{}
		problems []string
	)

	for _, family := range families {
		for _, method := range methods {
			start := time.Now()
			result, err := client.DiscoverWithMethod(ctx, method, family)
			elapsed := time.Since(start)
			if err != nil {
				if ctx.Err() != nil {
					// The budget is gone; report what was collected rather than
					// pretending the remaining probes were tried.
					problems = append(problems, fmt.Sprintf("%s/ipv%s: the %ds budget ran out", method, familyLabel(family), timeout))
					break
				}
				if verbose {
					problems = append(problems, fmt.Sprintf("%s/ipv%s: %v", method, familyLabel(family), firstCause(err)))
				}
				continue
			}
			// The first probe to report an address wins. All three methods usually see the
			// same address, so what --all should say is which one got there first in the
			// documented order — overwriting the map reported the last method instead.
			key := result.IP.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, found{result: result, latency: elapsed})
		}
		if ctx.Err() != nil {
			break
		}
	}

	if len(findings) == 0 {
		if verbose && len(problems) > 0 {
			for _, e := range problems {
				fmt.Fprintf(c.stderr, "  %s\n", e)
			}
		}
		return errors.New("no public IP could be discovered")
	}

	if asJSON {
		return c.encodeAllJSON(findings, problems)
	}
	for _, f := range findings {
		fmt.Fprintln(c.stdout, f.result.IP.String())
	}
	if verbose {
		for _, e := range problems {
			fmt.Fprintf(c.stderr, "  %s\n", e)
		}
	}
	return nil
}

func (c *cli) encodeJSON(results []publicip.Result, problems []string, elapsed time.Duration) error {
	out := jsonOutput{Errors: problems}
	for _, r := range results {
		out.Addresses = append(out.Addresses, jsonAddress{
			IP:      r.IP.String(),
			Method:  string(r.Method),
			Family:  versionLabel(r.Version),
			Latency: elapsed.Round(time.Millisecond).String(),
		})
	}

	enc := json.NewEncoder(c.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// encodeAllJSON writes one entry per address with the latency of the probe that found
// it, which is the point of --all --json over reading bare lines of stdout.
func (c *cli) encodeAllJSON(findings []found, problems []string) error {
	out := jsonOutput{Errors: problems}
	for _, f := range findings {
		out.Addresses = append(out.Addresses, jsonAddress{
			IP:      f.result.IP.String(),
			Method:  string(f.result.Method),
			Family:  versionLabel(f.result.Version),
			Latency: f.latency.Round(time.Millisecond).String(),
		})
	}

	enc := json.NewEncoder(c.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// describeFailure prints the per-target report, which is the reason v2 carries the
// causes at all: "no public IP could be discovered" after twenty attempts is a dead end
// without it.
func (c *cli) describeFailure(err error) {
	var de *publicip.DiscoveryError
	if !errors.As(err, &de) {
		return
	}
	if detail := strings.TrimSpace(de.Detail()); detail != "" {
		fmt.Fprintf(c.stderr, "attempts:\n%s\n", detail)
	}
}

func firstCause(err error) string {
	var de *publicip.DiscoveryError
	if errors.As(err, &de) {
		failures := de.Failures()
		if len(failures) > 0 {
			return failures[0].Err.Error()
		}
	}
	return err.Error()
}

func familyLabel(v publicip.IPVersion) string {
	if v == publicip.IPv6Only {
		return "6"
	}
	return "4"
}

func versionLabel(v publicip.IPVersion) string {
	if v == publicip.IPv6Only {
		return "ipv6"
	}
	return "ipv4"
}

func parseVersion(raw string) (publicip.IPVersion, error) {
	switch raw {
	case "":
		return publicip.Any, nil
	case "4":
		return publicip.IPv4Only, nil
	case "6":
		return publicip.IPv6Only, nil
	default:
		return publicip.Any, fmt.Errorf("invalid ip-version: %s (must be 4 or 6)", raw)
	}
}

func parseMethod(raw string) (publicip.Method, error) {
	switch strings.ToLower(raw) {
	case "":
		return "", nil
	case "stun":
		return publicip.STUN, nil
	case "dns":
		return publicip.DNS, nil
	case "http":
		return publicip.HTTP, nil
	default:
		return "", fmt.Errorf("invalid method: %s (must be stun, dns, or http)", raw)
	}
}

// main only wires the process boundaries: os.Args, os.Stdout, os.Exit. Everything it
// calls is run(), which is driven from tests with buffers and a fake client factory.
func main() { // coverage-ignore: process boundaries are asserted by the integration suite
	c := &cli{stdout: os.Stdout, stderr: os.Stderr, newClient: publicip.New}
	if err := c.run(os.Args[1:]); err != nil {
		fmt.Fprintf(c.stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
