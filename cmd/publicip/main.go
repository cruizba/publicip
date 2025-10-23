package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cruizba/publicip"
	"github.com/spf13/cobra"
)

var (
	ipVersion string
	method    string
	timeout   int
)

var rootCmd = &cobra.Command{
	Use:   "publicip",
	Short: "A CLI tool to discover your public IP address",
	Long: `publicip is a command line tool that helps you discover your public IP address 
using different methods like STUN and DNS, with support for both IPv4 and IPv6.`,
	RunE: func(cmd *cobra.Command, args []string) error {
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
		default:
			ipVer = publicip.Any
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
				return fmt.Errorf("invalid method: %s", method)
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
	},
}

func init() {
	rootCmd.Flags().StringVarP(&ipVersion, "ip-version", "v", "", "IP version to discover (4 or 6)")
	rootCmd.Flags().StringVarP(&method, "method", "m", "", "Discovery method (stun, dns, or http)")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "Timeout in seconds")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
