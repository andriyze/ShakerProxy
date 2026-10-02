package conntrack

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func attribute(kind uint16, value []byte) []byte {
	length := 4 + len(value)
	out := make([]byte, 4, align(length))
	binary.NativeEndian.PutUint16(out[0:2], uint16(length))
	binary.NativeEndian.PutUint16(out[2:4], kind)
	out = append(out, value...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

func nested(kind uint16, children ...[]byte) []byte {
	var value []byte
	for _, child := range children {
		value = append(value, child...)
	}
	return attribute(kind|0x8000, value)
}

func port(value uint16) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, value)
	return out
}

func message(messageType, flags uint16, family byte, attributes ...[]byte) []byte {
	body := []byte{family, 0, 0, 0}
	for _, item := range attributes {
		body = append(body, item...)
	}
	header := make([]byte, netlinkHeaderLength)
	binary.NativeEndian.PutUint32(header[0:4], uint32(netlinkHeaderLength+len(body)))
	binary.NativeEndian.PutUint16(header[4:6], messageType)
	binary.NativeEndian.PutUint16(header[6:8], flags)
	return append(header, body...)
}

func connection(source, destination string, protocol byte, sourcePort, destinationPort uint16) []byte {
	src, dst := netip.MustParseAddr(source), netip.MustParseAddr(destination)
	sourceKind, destinationKind := uint16(ctaIPv4Source), uint16(ctaIPv4Dest)
	family := byte(2)
	if src.Is6() {
		sourceKind, destinationKind, family = ctaIPv6Source, ctaIPv6Dest, 10
	}
	original := nested(ctaTupleOrig,
		nested(ctaTupleIP, attribute(sourceKind, src.AsSlice()), attribute(destinationKind, dst.AsSlice())),
		nested(ctaTupleProto, attribute(ctaProtoNumber, []byte{protocol}), attribute(ctaProtoSrcPort, port(sourcePort)), attribute(ctaProtoDstPort, port(destinationPort))),
	)
	// The reply tuple (after NAT) comes second and must not be confused
	// with the original direction.
	reply := nested(2,
		nested(ctaTupleIP, attribute(ctaIPv4Source, []byte{140, 82, 121, 4}), attribute(ctaIPv4Dest, []byte{192, 168, 10, 177})),
		nested(ctaTupleProto, attribute(ctaProtoNumber, []byte{protocol}), attribute(ctaProtoSrcPort, port(destinationPort)), attribute(ctaProtoDstPort, port(40000))),
	)
	return message(subsystemCTNetlink<<8|messageCTNew, netlinkFlagCreate|0x200, family, original, reply, attribute(12, []byte{0, 0, 0, 7}))
}

func TestParseMessagesReadsNewConnectionsInTheirOriginalDirection(t *testing.T) {
	datagram := append(connection("192.168.10.201", "140.82.121.4", 6, 37064, 443), connection("192.168.10.201", "142.250.1.1", 17, 50000, 443)...)
	datagram = append(datagram, connection("fd00::201", "2a00:1450::1", 58, 0, 0)...)
	// An update (no create flag) and a done message are skipped.
	datagram = append(datagram, message(subsystemCTNetlink<<8|messageCTNew, 0, 2, nested(ctaTupleOrig))...)
	datagram = append(datagram, message(netlinkMessageDone, 0, 0)...)
	events, err := ParseMessages(datagram)
	if err != nil {
		t.Fatal(err)
	}
	want := []Event{
		{Protocol: "tcp", Source: netip.MustParseAddrPort("192.168.10.201:37064"), Destination: netip.MustParseAddrPort("140.82.121.4:443")},
		{Protocol: "udp", Source: netip.MustParseAddrPort("192.168.10.201:50000"), Destination: netip.MustParseAddrPort("142.250.1.1:443")},
		{Protocol: "icmp", Source: netip.MustParseAddrPort("[fd00::201]:0"), Destination: netip.MustParseAddrPort("[2a00:1450::1]:0")},
	}
	if len(events) != len(want) {
		t.Fatalf("events = %+v", events)
	}
	for index := range want {
		if events[index] != want[index] {
			t.Fatalf("event %d = %+v, want %+v", index, events[index], want[index])
		}
	}
}

func TestParseMessagesRejectsTruncatedInput(t *testing.T) {
	full := connection("192.168.10.201", "140.82.121.4", 6, 37064, 443)
	for cut := 1; cut < len(full); cut++ {
		// Truncation must never panic; it may yield no event or an error.
		_, _ = ParseMessages(full[:cut])
	}
	broken := connection("192.168.10.201", "140.82.121.4", 6, 37064, 443)
	binary.NativeEndian.PutUint32(broken[0:4], uint32(len(broken)+40))
	if _, err := ParseMessages(broken); err == nil {
		t.Fatal("a message longer than its datagram was accepted")
	}
}
