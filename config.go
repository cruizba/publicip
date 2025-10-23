package publicip

import "time"

// Config holds the configuration for the IP discovery client
type Config struct {
	// RequestTimeout is the timeout for individual requests to services
	RequestTimeout time.Duration
	// STUNConfig holds STUN-specific configuration
	STUNConfig STUNConfig
	// DNSConfig holds DNS-specific configuration
	DNSConfig DNSConfig
	// HTTPConfig holds HTTP-specific configuration
	HTTPConfig HTTPConfig
}

// DefaultConfig returns a Config with sensible default values
func DefaultConfig() *Config {
	return &Config{
		RequestTimeout: 5 * time.Second,
		STUNConfig:     DefaultSTUNConfig(),
		DNSConfig:      DefaultDNSConfig(),
		HTTPConfig:     DefaultHTTPConfig(),
	}
}

// STUNConfig holds configuration specific to STUN discovery
type STUNConfig struct {
	Servers []string
}

// DefaultSTUNConfig returns STUNConfig with default values
func DefaultSTUNConfig() STUNConfig {
	return STUNConfig{
		Servers: []string{
			"stun.l.google.com:19302",
			"stun1.l.google.com:19302",
			"global.stun.twilio.com:3478",
		},
	}
}

// DNSConfig holds configuration specific to DNS discovery
type DNSConfig struct {
	Servers []string
}

// DefaultDNSConfig returns DNSConfig with default values
func DefaultDNSConfig() DNSConfig {
	return DNSConfig{
		Servers: []string{
			"resolver1.opendns.com:myip.opendns.com",
			"resolver2.opendns.com:myip.opendns.com",
			"ns1.google.com:o-o.myaddr.l.google.com",
			"ns1-1.akamaitech.net:whoami.akamai.net",
		},
	}
}

// HTTPConfig holds configuration specific to HTTP discovery
type HTTPConfig struct {
	Endpoints []string
}

// DefaultHTTPConfig returns HTTPConfig with default values
func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Endpoints: []string{
			"https://api.ipify.org",
			"https://ifconfig.me",
			"https://icanhazip.com",
		},
	}
}
