package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cruizba/publicip"
)

var (
	ipVersion   string
	method      string
	timeout     int
	showVersion bool
	showHelp    bool
)

func init() {
	// Long flags
	flag.StringVar(&ipVersion, "ip-version", "", "IP version to discover (4 or 6)")
	flag.StringVar(&method, "method", "", "Discovery method (stun, dns, or http)")
	flag.IntVar(&timeout, "timeout", 10, "Timeout in seconds")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.BoolVar(&showHelp, "help", false, "Show help")

	// Short flags (point to same variables)
	flag.StringVar(&ipVersion, "i", "", "IP version to discover (4 or 6)")
	flag.StringVar(&method, "m", "", "Discovery method (stun, dns, or http)")
	flag.IntVar(&timeout, "t", 10, "Timeout in seconds")
	flag.BoolVar(&showVersion, "v", false, "Show version information")
	flag.BoolVar(&showHelp, "h", false, "Show help")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `publicip - A CLI tool to discover your public IP address

publicip is a command line tool that helps you discover your public IP address
using different methods like STUN, DNS, and HTTP, with support for both IPv4 and IPv6.

Usage:
  publicip [flags]

Flags:
  -h, -help            Show help
  -i, -ip-version      IP version to discover (4 or 6)
  -m, -method          Discovery method (stun, dns, or http)
  -t, -timeout         Timeout in seconds (default 10)
  -v, -version         Show version information
`)
	}
}

func run() error {
	flag.Parse()

	if showHelp {
		flag.Usage()
		return nil
	}

	if showVersion {
		fmt.Println(publicip.GetVersion())
		return nil
	}

	client := publicip.NewClient()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// Parse IP version
	var ipVer publicip.IPVersion
	switch ipVersion {
	case "4":
		ipVer = publicip.IPv4Only
	case "6":
		ipVer = publicip.IPv6Only
	case "":
		ipVer = publicip.Any
	default:
		return fmt.Errorf("invalid ip-version: %s (must be 4 or 6)", ipVersion)
	}

	var ip net.IP
	var err error

	// If method is specified, use it with the IP version
	if method != "" {
		var m publicip.Method
		switch method {
		case "stun":
			m = publicip.STUN
		case "dns":
			m = publicip.DNS
		case "http":
			m = publicip.HTTP
		default:
			return fmt.Errorf("invalid method: %s (must be stun, dns, or http)", method)
		}

		ip, err = client.DiscoverWithMethod(ctx, m, ipVer)
	} else if ipVersion != "" {
		// If only IP version is specified
		ip, err = client.DiscoverWithIpVersion(ctx, ipVer)
	} else {
		// Basic discovery
		ip, err = client.Discover(ctx)
	}

	if err != nil {
		return err
	}

	fmt.Println(ip.String())
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}
}
