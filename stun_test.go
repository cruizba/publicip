package publicip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// --- helpers to build STUN messages by hand -------------------------------

// pad4 pads an attribute with zeros up to its 4-byte STUN boundary.
func pad4(attr []byte) []byte {
	if r := len(attr) % 4; r != 0 {
		return append(attr, make([]byte, 4-r)...)
	}
	return attr
}

// encodeStunAttr builds one attribute with its 4-byte padding.
func encodeStunAttr(typ uint16, value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(out[0:2], typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(value)))
	copy(out[4:], value)
	return out
}

// encodeAddressValue builds the value part of a MAPPED-ADDRESS /
// XOR-MAPPED-ADDRESS attribute for the given IP.
func encodeAddressValue(ip net.IP, family byte) []byte {
	v := make([]byte, 8)
	if family == familyIPv6 {
		v = make([]byte, 20)
	}
	v[1] = family
	if family == familyIPv4 {
		copy(v[4:8], ip.To4())
		return v
	}
	copy(v[4:20], ip.To16())
	return v
}

// buildResponse assembles a complete Binding Response with the given attributes.
func buildResponse(transactionID [12]byte, attrs ...[]byte) []byte {
	body := bytes.Join(attrs, nil)
	msg := make([]byte, stunHeaderSize+len(body))
	binary.BigEndian.PutUint16(msg[0:2], stunBindingResponse)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(body)))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], transactionID[:])
	copy(msg[stunHeaderSize:], body)
	return msg
}

func xorAddressValue(ip net.IP, transactionID [12]byte) []byte {
	if v4 := ip.To4(); v4 != nil {
		v := encodeAddressValue(v4, familyIPv4)
		key := []byte{0x21, 0x12, 0xA4, 0x42}
		for i := 0; i < 4; i++ {
			v[4+i] ^= key[i]
		}
		return v
	}
	v := encodeAddressValue(ip, familyIPv6)
	key := make([]byte, 16)
	binary.BigEndian.PutUint32(key[0:4], stunMagicCookie)
	copy(key[4:16], transactionID[:])
	for i := 0; i < 16; i++ {
		v[4+i] ^= key[i]
	}
	return v
}

// --- buildBindingRequest --------------------------------------------------

func TestBuildBindingRequest(t *testing.T) {
	msg, transactionID, err := buildBindingRequest(defaultEntropy)
	if err != nil {
		t.Fatalf("buildBindingRequest() error = %v", err)
	}

	if len(msg) != stunHeaderSize {
		t.Fatalf("len(msg) = %d, want %d", len(msg), stunHeaderSize)
	}
	// The literals below are the RFC 5389 values, deliberately not the package
	// constants: asserting against the constant would still pass when a mutant
	// changes the constant itself, which is the tautology mutation testing exists to
	// find.
	if got := binary.BigEndian.Uint16(msg[0:2]); got != 0x0001 {
		t.Errorf("message type = %#04x, want the Binding Request value 0x0001", got)
	}
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 0 {
		t.Errorf("message length = %d, want 0 (a Binding Request carries no attributes)", got)
	}
	if got := binary.BigEndian.Uint32(msg[4:8]); got != 0x2112A442 {
		t.Errorf("magic cookie = %#08x, want the RFC 5389 cookie 0x2112A442", got)
	}
	if !bytes.Equal(msg[8:20], transactionID[:]) {
		t.Errorf("transaction id %x not embedded in message %x", transactionID, msg[8:20])
	}
}

func TestBuildBindingRequestTransactionIDisRandom(t *testing.T) {
	_, first, err := buildBindingRequest(defaultEntropy)
	if err != nil {
		t.Fatalf("buildBindingRequest() error = %v", err)
	}
	_, second, err := buildBindingRequest(defaultEntropy)
	if err != nil {
		t.Fatalf("buildBindingRequest() error = %v", err)
	}
	if first == second {
		t.Fatal("two Binding Requests reused the same transaction id")
	}
}

// --- parseBindingResponse -------------------------------------------------

func TestParseBindingResponseErrors(t *testing.T) {
	var txn [12]byte
	binary.BigEndian.PutUint64(txn[:8], 0x0102030405060708)

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty datagram",
			data:    nil,
			wantErr: "response too short",
		},
		{
			name:    "shorter than header",
			data:    bytes.Repeat([]byte{0xff}, stunHeaderSize-1),
			wantErr: "response too short",
		},
		{
			name: "wrong message type", // an Indication, not a Success Response
			data: buildResponse(txn, encodeStunAttr(attrXORMappedAddress,
				xorAddressValue(net.IPv4(1, 2, 3, 4), txn))),
			wantErr: "unexpected message type",
		},
		{
			name: "missing magic cookie",
			data: func() []byte {
				m := buildResponse(txn)
				binary.BigEndian.PutUint32(m[4:8], 0xdeadbeef)
				return m
			}(),
			wantErr: "invalid magic cookie",
		},
		{
			name: "transaction id mismatch",
			data: func() []byte {
				m := buildResponse(txn)
				m[8] ^= 0xff
				return m
			}(),
			wantErr: "transaction ID mismatch",
		},
		{
			name: "declared length beyond datagram",
			data: func() []byte {
				m := buildResponse(txn, encodeStunAttr(attrXORMappedAddress,
					xorAddressValue(net.IPv4(1, 2, 3, 4), txn)))
				binary.BigEndian.PutUint16(m[2:4], uint16(len(m)+8))
				return m
			}(),
			wantErr: "message truncated",
		},
		{
			name:    "no mapped address attribute",
			data:    buildResponse(txn, encodeStunAttr(0x8028, []byte("fingerprints"))),
			wantErr: "no mapped address",
		},
		{
			name: "attribute length runs past the body",
			data: func() []byte {
				attr := encodeStunAttr(attrXORMappedAddress,
					xorAddressValue(net.IPv4(1, 2, 3, 4), txn))
				binary.BigEndian.PutUint16(attr[2:4], uint16(len(attr))) // lies about the length
				return buildResponse(txn, attr)
			}(),
			wantErr: "no mapped address",
		},
		{
			name:    "attribute header cut short",
			data:    buildResponse(txn, []byte{0x00, 0x20}),
			wantErr: "no mapped address",
		},
		{
			name: "unsupported address family",
			data: buildResponse(txn, encodeStunAttr(attrXORMappedAddress,
				[]byte{0x00, 0x7f, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})),
			wantErr: "no mapped address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fix up the one case that intentionally uses another message type.
			data := tt.data
			if tt.name == "wrong message type" {
				binary.BigEndian.PutUint16(data[0:2], 0x0016)
			}

			ip, err := parseBindingResponse(data, txn)
			if err == nil {
				t.Fatalf("parseBindingResponse() = %v, want error %q", ip, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseBindingResponseAddresses(t *testing.T) {
	var txn [12]byte
	binary.BigEndian.PutUint32(txn[:4], 0x11223344)
	binary.BigEndian.PutUint64(txn[4:], 0x5566778899aabbcc)

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "XOR-MAPPED-ADDRESS IPv4",
			data: buildResponse(txn, encodeStunAttr(attrXORMappedAddress,
				xorAddressValue(net.IPv4(203, 0, 113, 195), txn))),
			want: "203.0.113.195",
		},
		{
			name: "XOR-MAPPED-ADDRESS IPv6",
			data: buildResponse(txn, encodeStunAttr(attrXORMappedAddress,
				xorAddressValue(net.ParseIP("2001:db8::1"), txn))),
			want: "2001:db8::1",
		},
		{
			name: "MAPPED-ADDRESS IPv4",
			data: buildResponse(txn, encodeStunAttr(attrMappedAddress,
				encodeAddressValue(net.IPv4(198, 51, 100, 7), familyIPv4))),
			want: "198.51.100.7",
		},
		{
			name: "MAPPED-ADDRESS IPv6",
			data: buildResponse(txn, encodeStunAttr(attrMappedAddress,
				encodeAddressValue(net.ParseIP("2001:db8:ff::9"), familyIPv6))),
			want: "2001:db8:ff::9",
		},
		{
			name: "XOR wins over MAPPED when XOR comes first",
			data: buildResponse(txn,
				encodeStunAttr(attrXORMappedAddress, xorAddressValue(net.IPv4(1, 1, 1, 1), txn)),
				encodeStunAttr(attrMappedAddress, encodeAddressValue(net.IPv4(2, 2, 2, 2), familyIPv4))),
			want: "1.1.1.1",
		},
		{
			name: "XOR still wins when MAPPED comes first",
			data: buildResponse(txn,
				encodeStunAttr(attrMappedAddress, encodeAddressValue(net.IPv4(2, 2, 2, 2), familyIPv4)),
				encodeStunAttr(attrXORMappedAddress, xorAddressValue(net.IPv4(1, 1, 1, 1), txn))),
			want: "1.1.1.1",
		},
		{
			name: "unknown attributes are skipped and padding honoured",
			data: buildResponse(txn,
				pad4(encodeStunAttr(0x0006, []byte("nonce"))),
				pad4(encodeStunAttr(0x8028, []byte("software"))),
				encodeStunAttr(attrXORMappedAddress, xorAddressValue(net.IPv4(9, 9, 9, 9), txn))),
			want: "9.9.9.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := parseBindingResponse(tt.data, txn)
			if err != nil {
				t.Fatalf("parseBindingResponse() error = %v", err)
			}
			if got := ip.String(); got != tt.want {
				t.Errorf("ip = %s, want %s", got, tt.want)
			}
			// The attribute numbers the fixture relies on are pinned too: XOR is
			// 0x0020 and MAPPED 0x0001 in RFC 5389 and in the RFC 3489 fallback.
			if attrXORMappedAddress != 0x0020 || attrMappedAddress != 0x0001 {
				t.Fatalf("attribute types drifted: XOR=%#04x MAPPED=%#04x",
					attrXORMappedAddress, attrMappedAddress)
			}
			if stunBindingResponse != 0x0101 || stunHeaderSize != 20 {
				t.Fatalf("response type or header size drifted: %#04x / %d",
					stunBindingResponse, stunHeaderSize)
			}
			if familyIPv4 != 0x01 || familyIPv6 != 0x02 {
				t.Fatalf("address family octets drifted: %d / %d", familyIPv4, familyIPv6)
			}
		})
	}
}

func TestParseAddressAttributesGuards(t *testing.T) {
	var txn [12]byte
	ip4 := net.IPv4(1, 2, 3, 4)

	// Both parsers must reject anything shorter than an 8-byte header and any
	// unknown family, and the IPv6 variants must reject a truncated value.
	xorShort := xorAddressValue(ip4, txn)
	cases := []struct {
		name string
		got  net.IP
	}{
		{"parseXORMappedAddress too short", parseXORMappedAddress(xorShort[:4], txn)},
		{"parseXORMappedAddress bad family", parseXORMappedAddress([]byte{0, 9, 0, 0, 1, 2, 3, 4}, txn)},
		{"parseXORMappedAddress truncated IPv6", parseXORMappedAddress(append([]byte{0, familyIPv6, 0, 0}, make([]byte, 8)...), txn)},
		{"parseMappedAddress too short", parseMappedAddress([]byte{0, familyIPv4, 0, 0})},
		{"parseMappedAddress bad family", parseMappedAddress([]byte{0, 0x09, 0, 0, 1, 2, 3, 4})},
		{"parseMappedAddress truncated IPv6", parseMappedAddress(append([]byte{0, familyIPv6, 0, 0}, make([]byte, 8)...))},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != nil {
				t.Errorf("%s = %v, want nil", tt.name, tt.got)
			}
		})
	}
}

// --- fake STUN servers ----------------------------------------------------

type stunHandler func(conn *net.UDPConn, from *net.UDPAddr, req []byte)

// startStunServer runs a fake STUN server on the given network and returns its
// address plus a stop func.
func startStunServer(t *testing.T, network string, handler stunHandler) string {
	t.Helper()

	host := "127.0.0.1"
	if network == "udp6" {
		host = "::1"
	}

	laddr, err := net.ResolveUDPAddr(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("cannot resolve %s loopback: %v", network, err)
	}
	ln, err := net.ListenUDP(network, laddr)
	if err != nil {
		t.Skipf("no usable %s loopback on this host: %v", network, err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, from, err := ln.ReadFromUDP(buf)
			if err != nil {
				return // listener closed, or read deadline reached
			}
			handler(ln, from, buf[:n])
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	return ln.LocalAddr().String()
}

// answeringServer replies to every Binding Request with the requested address.
func answeringServer(ip net.IP) stunHandler {
	return func(conn *net.UDPConn, from *net.UDPAddr, req []byte) {
		if len(req) < stunHeaderSize {
			return
		}
		var txn [12]byte
		copy(txn[:], req[8:20])
		body := encodeStunAttr(attrXORMappedAddress, xorAddressValue(ip, txn))
		_, _ = conn.WriteToUDP(buildResponse(txn, body), from)
	}
}

// silentServer receives requests and never replies, to exercise the read timeout.
func silentServer(conn *net.UDPConn, from *net.UDPAddr, req []byte) {}

func stunClient(addr string, timeout time.Duration) *stunDiscoverer {
	return newSTUNDiscoverer(testConfig(WithSTUNServers(addr), attemptTimeout(timeout)))
}

func TestSTUNDiscoverIPv4AndIPv6(t *testing.T) {
	v4 := startStunServer(t, "udp4", answeringServer(net.IPv4(192, 0, 2, 44)))
	v6 := startStunServer(t, "udp6", answeringServer(net.ParseIP("2001:db8::dead")))

	tests := []struct {
		name    string
		servers []string
		version IPVersion
		want    string
	}{
		{
			name:    "IPv4 only",
			servers: []string{v4},
			version: IPv4Only,
			want:    "192.0.2.44",
		},
		{
			name:    "IPv6 only",
			servers: []string{v6},
			version: IPv6Only,
			want:    "2001:db8::dead",
		},
		{
			// Any prefers IPv6, so a reachable v6 server must win over the v4 one.
			name:    "Any prefers IPv6",
			servers: []string{v4, v6},
			version: Any,
			want:    "2001:db8::dead",
		},
		{
			// Any falls back to IPv4 when IPv6 is unavailable.
			name:    "Any falls back to IPv4",
			servers: []string{v4},
			version: Any,
			want:    "192.0.2.44",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newSTUNDiscoverer(testConfig(WithSTUNServers(tt.servers...), attemptTimeout(2*time.Second)))
			res, err := d.Discover(context.Background(), tt.version)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if got := res.IP.String(); got != tt.want {
				t.Errorf("Discover() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSTUNFallsThroughServerList(t *testing.T) {
	good := startStunServer(t, "udp4", answeringServer(net.IPv4(198, 51, 100, 3)))
	dead := startStunServer(t, "udp4", silentServer)

	d := newSTUNDiscoverer(testConfig(
		WithSTUNServers(dead, "127.0.0.1:1", good), attemptTimeout(150*time.Millisecond)))

	res, err := d.Discover(context.Background(), IPv4Only)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := res.IP.String(); got != "198.51.100.3" {
		t.Errorf("Discover() = %v, want the third server's answer 198.51.100.3", got)
	}
}

func TestSTUNAllServersFail(t *testing.T) {
	dead := startStunServer(t, "udp4", silentServer)
	d := stunClient(dead, 100*time.Millisecond)

	_, err := d.Discover(context.Background(), IPv4Only)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
}

func TestSTUNRejectsMismatchedAddressFamily(t *testing.T) {
	// The server answers a udp6 query with an IPv4 address: the discoverer must
	// refuse it instead of reporting an IPv4 address as if it were IPv6.
	v6addr := startStunServer(t, "udp6", answeringServer(net.IPv4(203, 0, 113, 1)))

	d := stunClient(v6addr, 500*time.Millisecond)
	_, err := d.Discover(context.Background(), IPv6Only)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound for a family mismatch", err)
	}
}

func TestSTUNDialFailureIsReported(t *testing.T) {
	d := stunClient("127.0.0.1:1", 100*time.Millisecond)
	_, err := d.Discover(context.Background(), IPv4Only)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
}

func TestSTUNMalformedResponse(t *testing.T) {
	garbage := func(conn *net.UDPConn, from *net.UDPAddr, req []byte) {
		_, _ = conn.WriteToUDP([]byte("not a stun message at all"), from)
	}
	addr := startStunServer(t, "udp4", garbage)

	d := stunClient(addr, 500*time.Millisecond)
	if _, err := d.Discover(context.Background(), IPv4Only); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
}

// --- the timeout fix ------------------------------------------------------

// errReader fails on Read, which is the only way to reach the entropy error path in
// buildBindingRequest: crypto/rand does not fail on demand.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestBuildBindingRequestReportsEntropyFailure(t *testing.T) {
	msg, transactionID, err := buildBindingRequest(errReader{})
	if err == nil {
		t.Fatal("buildBindingRequest() = nil error, want the reader's error")
	}
	if !strings.Contains(err.Error(), "no entropy") {
		t.Errorf("error = %v, want it to come from the reader", err)
	}
	if msg != nil {
		t.Errorf("message = %v, want nil when the transaction id could not be built", msg)
	}
	if transactionID != ([12]byte{}) {
		t.Errorf("transaction id = %x, want the zero value on failure", transactionID)
	}
}

func TestSTUNSurfaceEntropyFailureIsReportedPerTarget(t *testing.T) {
	addr := startStunServer(t, "udp4", answeringServer(net.IPv4(1, 1, 1, 1)))
	d := newSTUNDiscoverer(testConfig(WithSTUNServers(addr), attemptTimeout(time.Second), withRand(errReader{})))

	_, err := d.Discover(context.Background(), IPv4Only)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
	if !strings.Contains(err.Error(), "no entropy") {
		t.Errorf("error = %q, want the entropy failure to reach the report", err)
	}
}

// TestParseBindingResponseUnpaddedTrailingAttribute is the regression for the panic the
// fuzzer found: an attribute whose length is not a multiple of 4, ending the body, makes
// the 4-byte padding run past the message. Before the bound check this was
// "slice bounds out of range", reachable from any UDP packet carrying our transaction id
// — a malformed or careless STUN server could crash the caller.
func TestParseBindingResponseUnpaddedTrailingAttribute(t *testing.T) {
	var txn [12]byte
	binary.BigEndian.PutUint64(txn[:8], 0x0123456789abcdef)

	odd := encodeStunAttr(0x0006, []byte("abcde")) // 4+5 bytes, no padding
	good := encodeStunAttr(attrXORMappedAddress, xorAddressValue(net.IPv4(203, 0, 113, 3), txn))

	tests := []struct {
		name    string
		body    [][]byte
		want    string
		wantErr bool
	}{
		{
			// The exact shape that panicked: the only attribute is odd-sized.
			name:    "odd attribute alone",
			body:    [][]byte{odd},
			wantErr: true,
		},
		{
			// A good attribute first is still usable; the trailing malformed one ends
			// the walk without discarding what was already parsed.
			name: "good attribute then odd one",
			body: [][]byte{good, odd},
			want: "203.0.113.3",
		},
		{
			// An odd attribute in front of a good one misaligns it, so the message
			// carries no usable address — rejected, not crashed on.
			name:    "odd attribute then a following one",
			body:    [][]byte{odd, good},
			wantErr: true,
		},
		{
			name: "padded odd attribute parses both",
			body: [][]byte{pad4(odd), good},
			want: "203.0.113.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := parseBindingResponse(buildResponse(txn, tt.body...), txn)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseBindingResponse() = %v, want an error", ip)
				}
				if ip != nil {
					t.Errorf("address = %v alongside error %v", ip, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseBindingResponse() error = %v", err)
			}
			if got := ip.String(); got != tt.want {
				t.Errorf("address = %s, want %s", got, tt.want)
			}
		})
	}
}
