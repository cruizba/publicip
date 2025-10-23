package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cruizba/publicip"
)

func main() {
	// Create a new client
	client := publicip.NewClient()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to discover public IP
	ip, err := client.Discover(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Discovered IP: %s\n", ip)

	// Try to discover specifically IPv4 or IPv6
	ip, err = client.DiscoverWithIpVersion(ctx, publicip.Any)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Discovered IP with specific version: %s\n", ip)

	// Try to discover specifically IPv4
	ip, err = client.DiscoverWithMethod(ctx, publicip.STUN, publicip.IPv4Only)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Discovered IPv4 using STUN: %s\n", ip)

	// Try to discover specifically IPv6
	ip, err = client.DiscoverWithMethod(ctx, publicip.DNS, publicip.IPv6Only)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Discovered IPv6 using DNS: %s\n", ip)
}
