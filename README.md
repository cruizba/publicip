# publicip - Golang Public IP Discovery Library

A Go library for discovering your public IP address using multiple methods:
- STUN (Session Traversal Utilities for NAT)
- DNS queries
- HTTP requests


## Features

- Multiple discovery methods (STUN, DNS, HTTP)
- Support for both IPv4 and IPv6
- Configurable IP version preference
- Context support for timeouts and cancellation
- Fallback between methods

## CLI Installation and Usage

Install the CLI tool:

```bash
go install github.com/cruizba/publicip/cmd/publicip@latest
```

> You need to have your `$HOME/go/bin` directory in your system's `PATH` to run the installed binary directly.

Basic usage:
```bash
publicip
```

Options:
```
Flags:
  -i,  --ip-version string   IP version to discover (4 or 6)
  -m,  --method string       Discovery method (stun, dns, or http)
  -t,  --timeout int         Timeout in seconds (default 10)
  -v,  --version            Show version information
```

Examples:
```bash
# Discover IPv4 address
publicip -i 4

# Discover IPv6 address
publicip -i 6

# Use specific method (STUN)
publicip -m stun

# Use DNS method with custom timeout
publicip -m dns -t 5
```

## Library Installation

```bash
go get github.com/cruizba/publicip
```

## Usage

Basic usage:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/cruizba/publicip"
)

func main() {
    // Create a new client with default configuration
    client := publicip.NewClient()

    // Create context with overall timeout
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Discover any IP (IPv4 or IPv6)
    ip, err := client.Discover(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Discovered IP: %s\n", ip)
}
```

## Configuration

The library provides flexible configuration options through the `Config` struct:

```go
// Create a client with custom configuration
config := publicip.DefaultConfig()

// Configure request timeouts (default: 5 seconds)
config.RequestTimeout = 3 * time.Second

// Configure STUN servers
config.STUNConfig.Servers = []string{
    "stun.custom.com:3478",
    "stun.backup.com:3478",
}

// Configure DNS servers
config.DNSConfig.Servers = []string{
    "resolver1.custom.com",
    "resolver2.custom.com",
}

// Configure HTTP endpoints
config.HTTPConfig.Endpoints = []string{
    "https://custom.ip.service/ip",
    "https://backup.ip.service/ip",
}

// Create client with custom configuration
client := publicip.NewClientWithConfig(config)
```

### Configuration Options

1. Global Settings:
   - `RequestTimeout`: Timeout for individual service requests (default: 5 seconds)
   
2. STUN Configuration:
   - `STUNConfig.Servers`: List of default STUN servers.
   ```go
   []string{
       "stun.l.google.com:19302",
       "stun1.l.google.com:19302",
       "global.stun.twilio.com:3478",
   }
   ```

3. DNS Configuration:
   - `DNSConfig.Servers`: List of default DNS servers and query names.
   ```go
   // Default DNS servers
   []string{
        "resolver1.opendns.com:myip.opendns.com",
        "resolver2.opendns.com:myip.opendns.com",
        "ns1.google.com:o-o.myaddr.l.google.com",
        "ns1-1.akamaitech.net:whoami.akamai.net",
   }
   ```

   Each entry contains the DNS server address and the query name separated by a colon.

4. HTTP Configuration:
   - `HTTPConfig.Endpoints`: List of default HTTP endpoints.
   ```go
   []string{
       "https://api.ipify.org",
       "https://ifconfig.me",
       "https://icanhazip.com",
   }
   ```

### Timeout Handling

The library handles timeouts at two levels:

1. **Request Timeout**: Configured through `Config.RequestTimeout`
   - Applied individually to each service request
   - Controls how long each method (STUN/DNS/HTTP) can take
   - Default is 5 seconds

2. **Context Timeout**: Provided when calling discovery methods
   - Controls the overall operation timeout
   - Can be used to limit total discovery time
   ```go
   // Example: Limit overall discovery to 10 seconds
   ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
   defer cancel()
   ip, err := client.Discover(ctx, publicip.Any)
   ```

## Discovery Methods

The library supports three methods for IP discovery, tried in the following order:

1. **STUN (Session Traversal Utilities for NAT)**
   - Uses STUN protocol to discover your public IP
   - Fastest response time
   - Works with both IPv4 and IPv6
   ```go
   ip, err := client.DiscoverWithMethod(ctx, publicip.STUN, publicip.IPv4Only)
   ```

2. **DNS**
   - Uses DNS queries to special DNS servers
   - Good fallback option
   - Works reliably in most network configurations
   - Supports both IPv4 and IPv6
   ```go
   ip, err := client.DiscoverWithMethod(ctx, publicip.DNS, publicip.Any)
   ```

3. **HTTP**
   - Makes HTTP requests to IP discovery services
   - Most compatible method
   - Works through most proxies
   - Support depends on the service endpoints
   ```go
   ip, err := client.DiscoverWithMethod(ctx, publicip.HTTP, publicip.IPv6Only)
   ```

You can either:
- Use `Discover()` to try all methods in order until one succeeds
- Use `DiscoverWithMethod()` to use a specific method

## IP Version Selection

Control which IP version to discover:

- `publicip.Any`: Returns either IPv4 or IPv6 (default)
  ```go
  ip, err := client.Discover(ctx, publicip.Any)
  ```

- `publicip.IPv4Only`: Returns only IPv4 addresses
  ```go
  ip, err := client.Discover(ctx, publicip.IPv4Only)
  ```

- `publicip.IPv6Only`: Returns only IPv6 addresses
  ```go
  ip, err := client.Discover(ctx, publicip.IPv6Only)
  ```