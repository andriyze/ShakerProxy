package nflog

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func attribute(kind uint16, value []byte) []byte {
	length := 4 + len(value)
	out := make([]byte, align(length))
	binary.LittleEndian.PutUint16(out[0:2], uint16(length))
	binary.LittleEndian.PutUint16(out[2:4], kind)
	copy(out[4:], value)
	return out
}

func packetMessage(attributes ...[]byte) []byte {
	body := []byte{2, 0, 0x03, 0x55} // nfgenmsg: AF_INET, version 0, group 853
	for _, value := range attributes {
		body = append(body, value...)
	}
	message := make([]byte, nlmsgHeaderLen, nlmsgHeaderLen+len(body))
	binary.LittleEndian.PutUint32(message[0:4], uint32(nlmsgHeaderLen+len(body)))
	binary.LittleEndian.PutUint16(message[4:6], packetMsgType)
	return append(message, body...)
}

func ipv4TCP(source, destination string, sourcePort, destinationPort uint16) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x45
	packet[9] = 6
	copy(packet[12:16], netip.MustParseAddr(source).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(destination).AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	return packet
}

func ipv6UDP(source, destination string, sourcePort, destinationPort uint16) []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	packet[6] = 17
	copy(packet[8:24], netip.MustParseAddr(source).AsSlice())
	copy(packet[24:40], netip.MustParseAddr(destination).AsSlice())
	binary.BigEndian.PutUint16(packet[40:42], sourcePort)
	binary.BigEndian.PutUint16(packet[42:44], destinationPort)
	return packet
}

func TestLoggedPacketsAreDecoded(t *testing.T) {
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	hardware := append([]byte{0, 6, 0, 0}, 0x72, 0x58, 0x49, 0xe8, 0xe4, 0x00, 0, 0)
	timestamp := make([]byte, 16)
	binary.BigEndian.PutUint64(timestamp[0:8], uint64(now.Add(-time.Second).Unix()))
	first := packetMessage(
		attribute(attrPrefix, []byte("SHAKERPROXY_EDNS_DOH_TCP \x00")),
		attribute(attrHardwareAddr, hardware),
		attribute(attrTimestamp, timestamp),
		attribute(attrPayload, ipv4TCP("192.168.10.201", "1.1.1.1", 41234, 443)),
	)
	second := packetMessage(
		attribute(attrPrefix, []byte("SHAKERPROXY_EDNS_DOQ \x00")),
		attribute(attrPayload, ipv6UDP("fd00::201", "2606:4700:4700::1111", 50000, 853)),
	)
	packets, err := ParseMessages(append(first, second...), now)
	if err != nil || len(packets) != 2 {
		t.Fatalf("packets = %+v err=%v", packets, err)
	}
	if packets[0].Prefix != "SHAKERPROXY_EDNS_DOH_TCP " || packets[0].HardwareAddr.String() != "72:58:49:e8:e4:00" || !packets[0].Time.Equal(now.Add(-time.Second)) {
		t.Fatalf("first packet = %+v", packets[0])
	}
	flow, ok := ParseFlow(packets[0].Payload)
	if !ok || flow.Source.String() != "192.168.10.201" || flow.Destination.String() != "1.1.1.1" || flow.Protocol != "tcp" || flow.SourcePort != 41234 || flow.DestinationPort != 443 {
		t.Fatalf("IPv4 flow = %+v ok=%v", flow, ok)
	}
	if !packets[1].Time.Equal(now) {
		t.Fatalf("a packet without a kernel timestamp should use now: %v", packets[1].Time)
	}
	flow, ok = ParseFlow(packets[1].Payload)
	if !ok || flow.Destination.String() != "2606:4700:4700::1111" || flow.Protocol != "udp" || flow.DestinationPort != 853 {
		t.Fatalf("IPv6 flow = %+v ok=%v", flow, ok)
	}
}

func TestMalformedLogMessagesAreRejected(t *testing.T) {
	good := packetMessage(attribute(attrPrefix, []byte("X\x00")))
	truncated := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(truncated[0:4], uint32(len(good)+40))
	if _, err := ParseMessages(truncated, time.Now()); err == nil {
		t.Fatal("a message longer than the read was accepted")
	}
	badAttribute := packetMessage([]byte{200, 0, 10, 0})
	if _, err := ParseMessages(badAttribute, time.Now()); err == nil {
		t.Fatal("an attribute longer than its message was accepted")
	}
	longPrefix := packetMessage(attribute(attrPrefix, make([]byte, 100)))
	if _, err := ParseMessages(longPrefix, time.Now()); err == nil {
		t.Fatal("an unbounded prefix was accepted")
	}
	for _, payload := range [][]byte{nil, {0x45}, {0x60, 0}, {0x10, 0, 0}} {
		if _, ok := ParseFlow(payload); ok {
			t.Fatalf("payload %x parsed", payload)
		}
	}
	// Other netlink messages (acknowledgements) are skipped.
	other := make([]byte, nlmsgHeaderLen+4)
	binary.LittleEndian.PutUint32(other[0:4], uint32(len(other)))
	binary.LittleEndian.PutUint16(other[4:6], nlmsgError)
	if packets, err := ParseMessages(other, time.Now()); err != nil || len(packets) != 0 {
		t.Fatalf("non-packet message: %+v err=%v", packets, err)
	}
}
