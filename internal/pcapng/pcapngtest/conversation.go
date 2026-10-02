// Package pcapngtest builds small PCAPNG files of TCP conversations for
// tests of packet selection, reassembly and HTTP parsing.
package pcapngtest

import (
	"encoding/binary"
	"net/netip"
	"time"
)

const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
)

// Packet is one TCP packet of a conversation. Snap, when positive, captures
// only that many bytes of the frame, as a headers-only capture does.
type Packet struct {
	At         time.Time
	FromClient bool
	Seq        uint32
	Ack        uint32
	Flags      byte
	Payload    []byte
	Snap       int
}

// Conversation returns a little-endian PCAPNG file with one Ethernet
// interface (microsecond timestamps) holding the given packets between
// client and server.
func Conversation(client, server netip.AddrPort, packets []Packet) []byte {
	order := binary.LittleEndian
	file := sectionHeader(order)
	file = append(file, interfaceBlock(order)...)
	for _, packet := range packets {
		source, destination := client, server
		if !packet.FromClient {
			source, destination = server, client
		}
		frame := Frame(source, destination, packet.Seq, packet.Ack, packet.Flags, packet.Payload)
		file = append(file, enhancedPacket(order, frame, packet.At, packet.Snap)...)
	}
	return file
}

// Frame builds an Ethernet frame carrying one TCP segment over IPv4 or IPv6.
func Frame(source, destination netip.AddrPort, seq, ack uint32, flags byte, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], source.Port())
	binary.BigEndian.PutUint16(tcp[2:4], destination.Port())
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	ethernet := make([]byte, 14)
	copy(ethernet[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(ethernet[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	var ip []byte
	if source.Addr().Is4() {
		binary.BigEndian.PutUint16(ethernet[12:14], 0x0800)
		ip = make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
		binary.BigEndian.PutUint16(ip[6:8], 0x4000)
		ip[8] = 64
		ip[9] = 6
		from, to := source.Addr().As4(), destination.Addr().As4()
		copy(ip[12:16], from[:])
		copy(ip[16:20], to[:])
	} else {
		binary.BigEndian.PutUint16(ethernet[12:14], 0x86dd)
		ip = make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(tcp)))
		ip[6] = 6
		ip[7] = 64
		from, to := source.Addr().As16(), destination.Addr().As16()
		copy(ip[8:24], from[:])
		copy(ip[24:40], to[:])
	}
	return append(append(ethernet, ip...), tcp...)
}

func sectionHeader(order binary.ByteOrder) []byte {
	block := make([]byte, 28)
	copy(block[0:4], []byte{0x0a, 0x0d, 0x0d, 0x0a})
	order.PutUint32(block[4:8], uint32(len(block)))
	order.PutUint32(block[8:12], 0x1a2b3c4d)
	order.PutUint16(block[12:14], 1)
	for index := 16; index < 24; index++ {
		block[index] = 0xff
	}
	order.PutUint32(block[24:28], uint32(len(block)))
	return block
}

func interfaceBlock(order binary.ByteOrder) []byte {
	block := make([]byte, 20)
	order.PutUint32(block[0:4], 1)
	order.PutUint32(block[4:8], uint32(len(block)))
	order.PutUint16(block[8:10], 1)
	order.PutUint32(block[12:16], 262144)
	order.PutUint32(block[16:20], uint32(len(block)))
	return block
}

func enhancedPacket(order binary.ByteOrder, frame []byte, at time.Time, snap int) []byte {
	captured := frame
	if snap > 0 && snap < len(frame) {
		captured = frame[:snap]
	}
	timestamp := uint64(at.UnixMicro())
	padded := (len(captured) + 3) &^ 3
	block := make([]byte, 32+padded)
	order.PutUint32(block[0:4], 6)
	order.PutUint32(block[4:8], uint32(len(block)))
	order.PutUint32(block[12:16], uint32(timestamp>>32))
	order.PutUint32(block[16:20], uint32(timestamp))
	order.PutUint32(block[20:24], uint32(len(captured)))
	order.PutUint32(block[24:28], uint32(len(frame)))
	copy(block[28:], captured)
	order.PutUint32(block[len(block)-4:], uint32(len(block)))
	return block
}
