package publicip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// STUN message types (RFC 5389)
	stunBindingRequest  uint16 = 0x0001
	stunBindingResponse uint16 = 0x0101

	// STUN magic cookie (RFC 5389)
	stunMagicCookie uint32 = 0x2112A442

	// STUN attribute types
	attrMappedAddress    uint16 = 0x0001
	attrXORMappedAddress uint16 = 0x0020

	// Address families
	familyIPv4 byte = 0x01
	familyIPv6 byte = 0x02

	// Header size (20 bytes)
	stunHeaderSize = 20
)

// stunDiscoverer implements IP discovery using STUN protocol
type stunDiscoverer struct {
	cfg config
}

// newSTUNDiscoverer builds a discoverer for one method from the client configuration.
func newSTUNDiscoverer(cfg config) *stunDiscoverer {
	return &stunDiscoverer{cfg: cfg}
}

// buildBindingRequest creates a STUN Binding Request message. The entropy reader is a
// parameter so the transaction-id failure path is reachable from a test.
func buildBindingRequest(entropy io.Reader) ([]byte, [12]byte, error) {
	var transactionID [12]byte
	if _, err := io.ReadFull(entropy, transactionID[:]); err != nil {
		return nil, transactionID, err
	}

	msg := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(msg[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(msg[2:4], 0) // Message length: 0 (no attributes)
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], transactionID[:])

	return msg, transactionID, nil
}

// parseBindingResponse parses a STUN Binding Response and extracts the mapped address
func parseBindingResponse(data []byte, transactionID [12]byte) (net.IP, error) {
	if len(data) < stunHeaderSize {
		return nil, errors.New("stun: response too short")
	}

	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != stunBindingResponse {
		return nil, fmt.Errorf("stun: unexpected message type: 0x%04x", msgType)
	}

	cookie := binary.BigEndian.Uint32(data[4:8])
	if cookie != stunMagicCookie {
		return nil, errors.New("stun: invalid magic cookie")
	}

	if !bytes.Equal(data[8:20], transactionID[:]) {
		return nil, errors.New("stun: transaction ID mismatch")
	}

	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < stunHeaderSize+msgLen {
		return nil, errors.New("stun: message truncated")
	}

	attrs := data[stunHeaderSize : stunHeaderSize+msgLen]
	var ip net.IP

	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))

		if len(attrs) < 4+attrLen {
			break
		}

		attrValue := attrs[4 : 4+attrLen]

		switch attrType {
		case attrXORMappedAddress:
			ip = parseXORMappedAddress(attrValue, transactionID)
		case attrMappedAddress:
			if ip == nil { // Only use if XOR-MAPPED-ADDRESS not found
				ip = parseMappedAddress(attrValue)
			}
		}

		// Attributes are padded to 4-byte boundaries. The padding runs past the end of
		// the body when the final attribute is not padded: that is a malformed response,
		// not a reason to panic, so parsing stops and what was found stands.
		advance := 4 + attrLen + (4-(attrLen%4))%4
		if advance > len(attrs) {
			break
		}
		attrs = attrs[advance:]
	}

	if ip == nil {
		return nil, errors.New("stun: no mapped address in response")
	}

	return ip, nil
}

// parseXORMappedAddress parses an XOR-MAPPED-ADDRESS attribute
func parseXORMappedAddress(data []byte, transactionID [12]byte) net.IP {
	if len(data) < 8 {
		return nil
	}

	family := data[1]

	switch family {
	case familyIPv4:
		ip := make(net.IP, 4)
		// XOR with magic cookie bytes
		ip[0] = data[4] ^ 0x21
		ip[1] = data[5] ^ 0x12
		ip[2] = data[6] ^ 0xA4
		ip[3] = data[7] ^ 0x42
		return ip

	case familyIPv6:
		if len(data) < 20 {
			return nil
		}
		ip := make(net.IP, 16)
		// XOR with magic cookie + transaction ID
		xorKey := make([]byte, 16)
		binary.BigEndian.PutUint32(xorKey[0:4], stunMagicCookie)
		copy(xorKey[4:16], transactionID[:])
		for i := 0; i < 16; i++ {
			ip[i] = data[4+i] ^ xorKey[i]
		}
		return ip
	}

	return nil
}

// parseMappedAddress parses a MAPPED-ADDRESS attribute (fallback for old servers)
func parseMappedAddress(data []byte) net.IP {
	if len(data) < 8 {
		return nil
	}

	family := data[1]

	switch family {
	case familyIPv4:
		ip := make(net.IP, 4)
		copy(ip, data[4:8])
		return ip

	case familyIPv6:
		if len(data) < 20 {
			return nil
		}
		ip := make(net.IP, 16)
		copy(ip, data[4:20])
		return ip
	}

	return nil
}

// tryConnection sends a Binding Request to one STUN server over the forced family.
func (d *stunDiscoverer) tryConnection(ctx context.Context, server, family string, timeout time.Duration) (net.IP, error) {
	network := "udp" + family
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := d.cfg.dial(dialCtx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	request, transactionID, err := buildBindingRequest(d.cfg.rand)
	if err != nil {
		return nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	ip, err := parseBindingResponse(response[:n], transactionID)
	if err != nil {
		return nil, err
	}

	// Verify IP version matches the network type
	if mismatch := familyMismatch(ip, family); mismatch != nil {
		return nil, mismatch
	}

	return ip, nil
}

// Discover implements the Discoverer interface for STUN.
func (d *stunDiscoverer) Discover(ctx context.Context, version IPVersion) (Result, error) {
	return run(&d.cfg, ctx, STUN, d.cfg.stunServers, version, d.tryConnection, identity)
}
