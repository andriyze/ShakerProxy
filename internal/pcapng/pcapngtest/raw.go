package pcapngtest

import (
	"encoding/binary"
	"time"
)

// RawPacket is one captured frame of any link type.
type RawPacket struct {
	At   time.Time
	Data []byte
}

// File returns a little-endian PCAPNG file with one interface of the given
// link type (microsecond timestamps) holding the packets.
func File(linkType uint16, packets []RawPacket) []byte {
	order := binary.LittleEndian
	file := sectionHeader(order)
	block := interfaceBlock(order)
	order.PutUint16(block[8:10], linkType)
	file = append(file, block...)
	for _, packet := range packets {
		file = append(file, enhancedPacket(order, packet.Data, packet.At, 0)...)
	}
	return file
}
