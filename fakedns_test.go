package publicip

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// A minimal DNS responder, enough for the "what is my address" query shape: it parses
// the question, answers A and AAAA from a fixture table, and returns NOERROR with zero
// answers for anything else.
//
// This exists because v2 lets a DNSServer name its port. In v1 the resolver was always
// dialed on :53, which needs privileges a test does not have, so systemLookup and the
// whole happy path of tryQuery were untestable.

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
)

// dnsName extracts the first question's name and the end offset of the question section.
func dnsName(query []byte) (string, int, bool) {
	if len(query) < 12 {
		return "", 0, false
	}
	if binary.BigEndian.Uint16(query[4:6]) != 1 { // one question, the only case we need
		return "", 0, false
	}

	var name strings.Builder
	i := 12
	for {
		if i >= len(query) {
			return "", 0, false
		}
		length := int(query[i])
		if length == 0 {
			i++
			break
		}
		if length&0xc0 != 0 { // compression pointer: not used in queries
			return "", 0, false
		}
		i++
		if i+length > len(query) {
			return "", 0, false
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(query[i : i+length])
		i += length
	}

	if i+4 > len(query) { // qtype + qclass
		return "", 0, false
	}
	return name.String(), i + 4, true
}

// dnsAnswer builds a response echoing the question and carrying the given addresses.
func dnsAnswer(query []byte, ips []net.IP) []byte {
	end := 12
	if _, qend, ok := dnsName(query); ok {
		end = qend
	}
	question := query[12:end]

	resp := make([]byte, 12, 12+len(question)+len(ips)*40)
	binary.BigEndian.PutUint16(resp[0:2], binary.BigEndian.Uint16(query[0:2])) // same id
	binary.BigEndian.PutUint16(resp[2:4], 0x8180)                              // response, recursion available
	binary.BigEndian.PutUint16(resp[4:6], 1)                                   // qdcount
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(ips)))                    // ancount
	resp = append(resp, question...)

	for _, ip := range ips {
		recordType := uint16(dnsTypeAAAA)
		rdata := ip.To16()
		if v4 := ip.To4(); v4 != nil {
			recordType, rdata = dnsTypeA, v4
		}

		// An RR is NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 12 header bytes
		// followed by the rdata.
		answer := make([]byte, 12+len(rdata))
		binary.BigEndian.PutUint16(answer[0:2], 0xc00c) // name pointer to the question
		binary.BigEndian.PutUint16(answer[2:4], recordType)
		binary.BigEndian.PutUint16(answer[4:6], 1) // class IN
		binary.BigEndian.PutUint32(answer[6:10], 0)
		binary.BigEndian.PutUint16(answer[10:12], uint16(len(rdata)))
		copy(answer[12:], rdata)
		resp = append(resp, answer...)
	}
	return resp
}

// startFakeDNS listens on an IPv4 loopback UDP port and answers queries from the fixture
// table. It returns the "host:port" to dial.
func startFakeDNS(t *testing.T, answers map[string][]net.IP) string {
	t.Helper()
	return startFakeDNSOn(t, "udp", net.IPv4(127, 0, 0, 1), answers)
}

// startFakeDNSOn is the general form: the network and bind address decide which family
// can reach it, which is how a test drives the IPv6 path without a routable IPv6
// network. Answers are filtered by the record type that was asked for, so a fixture that
// serves only AAAA is what an IPv6 attempt will find.
func startFakeDNSOn(t *testing.T, network string, bindIP net.IP, answers map[string][]net.IP) string {
	t.Helper()

	ln, err := net.ListenUDP(network, &net.UDPAddr{IP: bindIP})
	if err != nil {
		t.Skipf("no %s loopback on this host: %v", network, err)
	}

	go func() {
		defer ln.Close()
		buf := make([]byte, 512)
		for {
			if err := ln.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				return
			}
			n, from, err := ln.ReadFromUDP(buf)
			if err != nil {
				return // listener closed, or the read deadline passed
			}
			query := append([]byte(nil), buf[:n]...)
			name, _, ok := dnsName(query)
			if !ok {
				continue
			}
			_, qtype, _ := dnsQuestion(query)

			var matched []net.IP
			for _, ip := range answers[name] {
				wantV4 := qtype == dnsTypeA
				if wantV4 == (ip.To4() != nil) {
					matched = append(matched, ip)
				}
			}
			_, _ = ln.WriteToUDP(dnsAnswer(query, matched), from)
		}
	}()

	t.Cleanup(func() { _ = ln.Close() })
	return ln.LocalAddr().String()
}

// dnsQuestion returns the qtype of the single question, after the name.
func dnsQuestion(query []byte) (name string, qtype uint16, ok bool) {
	name, end, ok := dnsName(query)
	if !ok {
		return "", 0, false
	}
	return name, binary.BigEndian.Uint16(query[end-4 : end-2]), true
}
