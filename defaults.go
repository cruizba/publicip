package publicip

// The shipped defaults. They live here, unexported, so that adding or retiring an
// endpoint is a one-line change rather than a new method on an exported config type.
var (
	defaultMethods = []Method{STUN, DNS, HTTP}

	// STUN servers, "host:port". Both Google endpoints answer IPv4 and IPv6.
	defaultSTUNServers = []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"global.stun.twilio.com:3478",
	}

	// DNS services that answer with the caller's address.
	defaultDNSServers = []DNSServer{
		{Addr: "resolver1.opendns.com", QueryName: "myip.opendns.com"},
		{Addr: "resolver2.opendns.com", QueryName: "myip.opendns.com"},
		{Addr: "ns1.google.com", QueryName: "o-o.myaddr.l.google.com"},
		{Addr: "ns1-1.akamaitech.net", QueryName: "whoami.akamai.net"},
	}

	// HTTP echo services. api.ipify.org has no AAAA record, so the IPv6 attempt for it
	// is expected to fail over rather than answer.
	defaultHTTPEndpoints = []string{
		"https://api.ipify.org",
		"https://ifconfig.me",
		"https://icanhazip.com",
	}
)
