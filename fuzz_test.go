package publicip

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// Fuzzing the wire parsers is the cheap half of "prove the tests have teeth": the STUN
// codec is hand-rolled byte manipulation over data that arrives from the network, and
// every branch that rejects a response is a branch where a panic or a wrong address
// would be a security bug rather than a bad day.
//
// The seed corpus lives in testdata/fuzz/, so a crash found on a developer machine or in
// CI stays in the repository as a regression test.

func buildResponseFor(txn [12]byte, body []byte) []byte {
	msg := make([]byte, stunHeaderSize+len(body))
	binary.BigEndian.PutUint16(msg[0:2], stunBindingResponse)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(body)))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txn[:])
	copy(msg[stunHeaderSize:], body)
	return msg
}

func FuzzParseBindingResponse(f *testing.F) {
	var txn [12]byte
	binary.BigEndian.PutUint64(txn[:8], 0xfeedfacecafebeef)

	// Seeds: the shapes a real server sends, plus the ways they go wrong.
	f.Add(buildResponseFor(txn, encodeStunAttr(attrXORMappedAddress,
		xorAddressValue(net.IPv4(203, 0, 113, 1), txn))))
	f.Add(buildResponseFor(txn, encodeStunAttr(attrMappedAddress,
		encodeAddressValue(net.IPv4(198, 51, 100, 1), familyIPv4))))
	f.Add(buildResponseFor(txn, encodeStunAttr(attrXORMappedAddress,
		xorAddressValue(net.ParseIP("2001:db8::1"), txn))))
	f.Add(buildResponseFor(txn, nil))
	f.Add(buildResponseFor(txn, []byte{0x00, 0x20}))
	f.Add(buildResponseFor(txn, encodeStunAttr(0x0001, []byte{1, 2, 3, 4, 5})))
	f.Add(bytes.Repeat([]byte{0xff}, 40))
	f.Add([]byte{})
	f.Add([]byte{0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		ip, err := parseBindingResponse(data, txn)
		if err != nil {
			if ip != nil {
				t.Fatalf("parseBindingResponse returned %v alongside error %v", ip, err)
			}
			return
		}
		// A successful parse must yield a usable address; anything else is a panic
		// waiting to happen in a caller that prints or compares it.
		if ip == nil {
			t.Fatal("parseBindingResponse returned no error and no address")
		}
		if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
			t.Fatalf("parsed address has length %d: % x", len(ip), []byte(ip))
		}
	})
}

func FuzzParseXORMappedAddress(f *testing.F) {
	var txn [12]byte
	binary.BigEndian.PutUint64(txn[:8], 0x0102030405060708)

	f.Add(xorAddressValue(net.IPv4(192, 0, 2, 1), txn))
	f.Add(xorAddressValue(net.ParseIP("2001:db8::1"), txn))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x00}, 8))
	f.Add(bytes.Repeat([]byte{0xff}, 20))
	f.Add([]byte{0x00, familyIPv6, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		ip := parseXORMappedAddress(data, txn)
		if ip == nil {
			return // rejected, which is a valid outcome
		}
		if len(ip) != 4 && len(ip) != 16 {
			t.Fatalf("address of length %d: % x", len(ip), []byte(ip))
		}
	})
}

func FuzzParseMappedAddress(f *testing.F) {
	f.Add(encodeAddressValue(net.IPv4(192, 0, 2, 2), familyIPv4))
	f.Add(encodeAddressValue(net.ParseIP("2001:db8::2"), familyIPv6))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01})
	f.Add(bytes.Repeat([]byte{0x01}, 20))

	f.Fuzz(func(t *testing.T, data []byte) {
		ip := parseMappedAddress(data)
		if ip == nil {
			return
		}
		if len(ip) != 4 && len(ip) != 16 {
			t.Fatalf("address of length %d: % x", len(ip), []byte(ip))
		}
	})
}

func FuzzParseAddressBody(f *testing.F) {
	f.Add([]byte("203.0.113.9\n"))
	f.Add([]byte("  2001:db8::1 \t\n"))
	f.Add([]byte(""))
	f.Add([]byte("\xc0\xc0"))
	f.Add([]byte("::ffff:192.0.2.7"))
	f.Add([]byte("999.1.1.1"))

	f.Fuzz(func(t *testing.T, body []byte) {
		ip, err := parseAddressBody(body)
		if err != nil {
			if ip != nil {
				t.Fatalf("parseAddressBody returned %v alongside error %v", ip, err)
			}
			return
		}
		if got := ip.String(); got == "" {
			t.Fatal("parsed address renders as empty")
		}
	})
}
