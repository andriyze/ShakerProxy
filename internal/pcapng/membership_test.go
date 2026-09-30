package pcapng

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestInspectFindsDeterministicEthernetMembership(t *testing.T) {
	contents := append(sectionHeader(binary.LittleEndian), interfaceBlock(binary.LittleEndian, 1)...)
	contents = append(contents, enhancedPacket(binary.LittleEndian, ethernetIPv4Packet(true))...)
	contents = append(contents, enhancedPacket(binary.LittleEndian, ethernetIPv6Packet())...)

	membership, err := Inspect(bytes.NewReader(contents))
	if err != nil {
		t.Fatal(err)
	}
	if !membership.Exact() || membership.PacketCount != 2 || len(membership.LinkTypes) != 1 || membership.LinkTypes[0] != 1 {
		t.Fatalf("unexpected membership summary: %#v", membership)
	}
	expectedMACs := []string{"02:00:00:00:00:01", "02:00:00:00:00:02"}
	expectedIPs := []string{"10.77.0.1", "10.77.0.111", "2001:db8::1", "2001:db8::2"}
	if !equalStrings(membership.MACAddresses, expectedMACs) || !equalStrings(membership.IPAddresses, expectedIPs) {
		t.Fatalf("unexpected exact identities: %#v", membership)
	}
	if err := membership.Validate(); err != nil {
		t.Fatalf("membership did not validate: %v", err)
	}
}

func TestInspectHandlesSectionsWithDifferentByteOrder(t *testing.T) {
	contents := append(sectionHeader(binary.LittleEndian), interfaceBlock(binary.LittleEndian, 1)...)
	contents = append(contents, enhancedPacket(binary.LittleEndian, ethernetIPv4Packet(false))...)
	contents = append(contents, sectionHeader(binary.BigEndian)...)
	contents = append(contents, interfaceBlock(binary.BigEndian, 101)...)
	contents = append(contents, enhancedPacket(binary.BigEndian, ipv4Packet())...)
	membership, err := Inspect(bytes.NewReader(contents))
	if err != nil || !membership.Exact() || membership.PacketCount != 2 || len(membership.LinkTypes) != 2 || membership.LinkTypes[0] != 1 || membership.LinkTypes[1] != 101 {
		t.Fatalf("mixed-endian sections were not inspected exactly: %#v err=%v", membership, err)
	}
}

func TestInspectDoesNotClaimExactnessForUnsupportedOrTruncatedHeaders(t *testing.T) {
	for name, testCase := range map[string]struct {
		linkType uint16
		packet   []byte
		expected MembershipState
	}{
		"unsupported link type": {147, []byte{1, 2, 3, 4}, MembershipUnsupportedLinkType},
		"truncated ethernet":    {1, []byte{1, 2, 3, 4}, MembershipPacketHeaders},
	} {
		t.Run(name, func(t *testing.T) {
			contents := append(sectionHeader(binary.LittleEndian), interfaceBlock(binary.LittleEndian, testCase.linkType)...)
			contents = append(contents, enhancedPacket(binary.LittleEndian, testCase.packet)...)
			membership, err := Inspect(bytes.NewReader(contents))
			if err != nil || membership.State != testCase.expected || membership.Exact() {
				t.Fatalf("inexact packet population was misreported: %#v err=%v", membership, err)
			}
		})
	}
}

func TestInspectRejectsMalformedPCAPNG(t *testing.T) {
	contents := sectionHeader(binary.LittleEndian)
	binary.LittleEndian.PutUint32(contents[len(contents)-4:], 24)
	if _, err := Inspect(bytes.NewReader(contents)); !errors.Is(err, ErrInvalidPCAPNG) {
		t.Fatalf("malformed block was accepted: %v", err)
	}
	if unavailable := Unavailable(MembershipInvalidPCAPNG); unavailable.Validate() != nil || unavailable.Exact() {
		t.Fatalf("invalid-PCAP state is not a valid explicit limitation: %#v", unavailable)
	}
}

func FuzzInspectNeverPanics(f *testing.F) {
	f.Add([]byte{})
	f.Add(sectionHeader(binary.LittleEndian))
	valid := append(sectionHeader(binary.LittleEndian), interfaceBlock(binary.LittleEndian, 1)...)
	f.Add(append(valid, enhancedPacket(binary.LittleEndian, ethernetIPv4Packet(false))...))
	f.Fuzz(func(t *testing.T, contents []byte) {
		membership, err := Inspect(bytes.NewReader(contents))
		if err == nil && membership.Validate() != nil {
			t.Fatalf("successful inspection returned invalid membership: %#v", membership)
		}
	})
}

func sectionHeader(order binary.ByteOrder) []byte {
	block := make([]byte, 28)
	copy(block[0:4], []byte{0x0a, 0x0d, 0x0d, 0x0a})
	order.PutUint32(block[4:8], uint32(len(block)))
	order.PutUint32(block[8:12], 0x1a2b3c4d)
	order.PutUint16(block[12:14], 1)
	order.PutUint16(block[14:16], 0)
	for index := 16; index < 24; index++ {
		block[index] = 0xff
	}
	order.PutUint32(block[24:28], uint32(len(block)))
	return block
}

func interfaceBlock(order binary.ByteOrder, linkType uint16) []byte {
	block := make([]byte, 20)
	order.PutUint32(block[0:4], 1)
	order.PutUint32(block[4:8], uint32(len(block)))
	order.PutUint16(block[8:10], linkType)
	order.PutUint32(block[12:16], 262144)
	order.PutUint32(block[16:20], uint32(len(block)))
	return block
}

func enhancedPacket(order binary.ByteOrder, packet []byte) []byte {
	return enhancedPacketAt(order, packet, 0)
}

func enhancedPacketAt(order binary.ByteOrder, packet []byte, timestamp uint64) []byte {
	padded := (len(packet) + 3) &^ 3
	block := make([]byte, 32+padded)
	order.PutUint32(block[0:4], 6)
	order.PutUint32(block[4:8], uint32(len(block)))
	order.PutUint32(block[8:12], 0)
	order.PutUint32(block[12:16], uint32(timestamp>>32))
	order.PutUint32(block[16:20], uint32(timestamp))
	order.PutUint32(block[20:24], uint32(len(packet)))
	order.PutUint32(block[24:28], uint32(len(packet)))
	copy(block[28:28+len(packet)], packet)
	order.PutUint32(block[len(block)-4:], uint32(len(block)))
	return block
}

func ethernetIPv4Packet(vlan bool) []byte {
	ip := ipv4Packet()
	header := make([]byte, 14)
	copy(header[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(header[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	if !vlan {
		binary.BigEndian.PutUint16(header[12:14], 0x0800)
		return append(header, ip...)
	}
	binary.BigEndian.PutUint16(header[12:14], 0x8100)
	header = append(header, 0, 7, 0x08, 0x00)
	return append(header, ip...)
}

func ipv4Packet() []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[12:16], []byte{10, 77, 0, 111})
	copy(packet[16:20], []byte{10, 77, 0, 1})
	return packet
}

func ethernetIPv6Packet() []byte {
	packet := make([]byte, 14+40)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
	packet[14] = 0x60
	copy(packet[22:38], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(packet[38:54], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	return packet
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
