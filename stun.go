package publicip

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun"
)

// stunDiscoverer implements IP discovery using STUN protocol
type stunDiscoverer struct {
	requestTimeout time.Duration
	config         STUNConfig
}

// newSTUNDiscovererWithConfig creates a new STUN-based IP discoverer with the provided configuration
func newSTUNDiscovererWithConfig(timeout time.Duration, config STUNConfig) *stunDiscoverer {
	return &stunDiscoverer{
		requestTimeout: timeout,
		config:         config,
	}
}

// tryConnection attempts to establish a STUN connection using the specified network type
func (d *stunDiscoverer) tryConnection(ctx context.Context, server, network string) (net.IP, error) {
	dialer := net.Dialer{
		Timeout:       d.requestTimeout,
		FallbackDelay: -1, // Disable IPv4 fallback when requesting IPv6
	}

	conn, err := dialer.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client, err := stun.NewClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var ip net.IP
	err = client.Do(stun.MustBuild(stun.TransactionID, stun.BindingRequest), func(res stun.Event) {
		if res.Error != nil {
			err = res.Error
			return
		}
		var xorAddr stun.XORMappedAddress
		if getErr := xorAddr.GetFrom(res.Message); getErr != nil {
			err = getErr
			return
		}
		ip = xorAddr.IP
	})
	if err != nil {
		return nil, err
	}

	// Verify IP version matches the network type
	isIPv4 := ip.To4() != nil
	if (network == "udp4" && !isIPv4) || (network == "udp6" && isIPv4) {
		return nil, fmt.Errorf("IP version mismatch: got IPv%d when requesting IPv%d",
			map[bool]int{true: 4, false: 6}[isIPv4],
			map[string]int{"udp4": 4, "udp6": 6}[network])
	}
	return ip, nil
}

// Discover implements the Discoverer interface for STUN
func (d *stunDiscoverer) Discover(ctx context.Context, version IPVersion) (net.IP, error) {
	if version == Any || version == IPv6Only {
		for _, server := range d.config.Servers {
			ip, err := d.tryConnection(ctx, server, "udp6")
			if err == nil {
				return ip, nil
			}
			logDebug("IPv6 connection failed for %s: %v", server, err)
		}
	}
	if version == Any || version == IPv4Only {
		for _, server := range d.config.Servers {
			ip, err := d.tryConnection(ctx, server, "udp4")
			if err == nil {
				return ip, nil
			}
			logDebug("IPv4 connection failed for %s: %v", server, err)
		}
	}
	logDebug("All STUN servers failed to discover IP")
	return nil, ErrNoIPDiscovered
}
