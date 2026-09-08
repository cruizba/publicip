package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cruizba/publicip/v2"
)

func main() {
	// Create a new client
	client := publicip.New()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to discover public IP
	result, err := client.Discover(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Discovered: %s\n", result)

	// Try to discover specifically IPv4 or IPv6
	result, err = client.DiscoverWithIPVersion(ctx, publicip.Any)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Any family: %s\n", result)

	// Try to discover specifically IPv4
	result, err = client.DiscoverWithMethod(ctx, publicip.STUN, publicip.IPv4Only)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("IPv4 over STUN: %s\n", result.IP)

	// Try to discover specifically IPv6
	result, err = client.DiscoverWithMethod(ctx, publicip.DNS, publicip.IPv6Only)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("IPv6 over DNS: %s\n", result.IP)
}
